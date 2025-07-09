import boto3
import subprocess
import sys
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from rich import box
from rich.text import Text
from rich.align import Align
import click
import questionary

console = Console()

# Helper to run AWS SSO login if needed
def ensure_sso_login(profile):
    try:
        session = boto3.Session(profile_name=profile)
        sts = session.client('sts')
        sts.get_caller_identity()
    except Exception:
        console.print("[yellow]SSO session expired or not found. Running 'aws sso login'...[/yellow]")
        subprocess.run(["aws", "sso", "login", "--profile", profile], check=True)

# Get EC2 instances
def get_instances(profile, region):
    session = boto3.Session(profile_name=profile, region_name=region)
    ec2 = session.resource('ec2')
    return list(ec2.instances.all())

# Display instances in a table
def display_instances(instances):
    table = Table(title="EC2 Instances", box=box.ROUNDED)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("State", style="magenta")
    table.add_column("Name", style="green")
    table.add_column("Type", style="yellow")
    for inst in instances:
        name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
        table.add_row(inst.id, inst.state['Name'], name, inst.instance_type)
    console.print(table)

def select_instance(instances):
    from rich.columns import Columns
    items = []
    for inst in instances:
        name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
        label = f"[cyan]{inst.id}[/cyan] [green]{name}[/green] [magenta]{inst.state['Name']}[/magenta]"
        items.append(Panel(label, style="bold", expand=False))
    console.print(Columns(items, equal=True))
    ids = [inst.id for inst in instances]
    sel = Prompt.ask("Enter instance ID to select", choices=ids)
    for inst in instances:
        if inst.id == sel:
            return inst

# New: Interactive instance picker for info view
def pick_instance_interactive(instances):
    choices = []
    for inst in instances:
        name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
        label = f"{inst.id} | {name} | {inst.state['Name']}"
        choices.append(questionary.Choice(title=label, value=inst))
    if not choices:
        return None
    return questionary.select("Select an instance to view details:", choices=choices).ask()

@click.group()
def cli():
    pass


@cli.command()
@click.option('--profile', prompt=True, help='AWS CLI profile')
@click.option('--region', prompt=True, help='AWS region')
def dashboard(profile, region):
    ensure_sso_login(profile)
    def get_account_id(profile, region):
        try:
            session = boto3.Session(profile_name=profile, region_name=region)
            sts = session.client('sts')
            return sts.get_caller_identity().get('Account', '-')
        except Exception:
            return '-'

    while True:
        account_id = get_account_id(profile, region)
        title = f"[bold cyan]CloudOps EC2 Dashboard[/bold cyan]\nProfile: [yellow]{profile}[/yellow] | Account: [green]{account_id}[/green] | Region: [magenta]{region}[/magenta]"
        console.print(Panel(title, expand=False))
        import questionary
        menu = [
            "List EC2 instances",
            "Start/Stop an instance",
            "View instance details",
            "View/Edit instance tags",
            "Instance Lookup",
            "Run Shell Command (SSM)",
            "Run SSM Document (ERApp)",
            "Switch Profile",
            "Exit"
        ]
        if choice == "Run SSM Document (ERApp)":
            instances = get_instances(profile, region)
            if not instances:
                console.print("[red]No instances found.[/red]")
                continue
            session = boto3.Session(profile_name=profile, region_name=region)
            ssm = session.client('ssm')
            # Get SSM documents with tag ERApp=true
            try:
                paginator = ssm.get_paginator('list_documents')
                docs = []
                for page in paginator.paginate(Filters=[{"Key": "Owner", "Values": ["Self"]}]):
                    for doc in page.get('DocumentIdentifiers', []):
                        doc_name = doc['Name']
                        # Get tags for this document
                        tags = ssm.list_tags_for_resource(ResourceType='Document', ResourceId=doc_name).get('TagList', [])
                        if any(t['Key'] == 'ERApp' and t['Value'] == 'true' for t in tags):
                            docs.append(doc)
                if not docs:
                    console.print("[yellow]No SSM documents found with tag ERApp=true.[/yellow]")
                    continue
                doc_choices = [questionary.Choice(title=f"{doc['Name']} ({doc['DocumentType']})", value=doc['Name']) for doc in docs]
                doc_name = questionary.select("Select SSM Document to run:", choices=doc_choices).ask()
                if not doc_name:
                    continue
                # Select instance(s) to run on
                instance_choices = []
                for inst in instances:
                    name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
                    label = f"{inst.id} | {name}"
                    instance_choices.append(questionary.Choice(title=label, value=inst.id))
                instance_id = questionary.select("Select an instance to run the document:", choices=instance_choices).ask()
                if not instance_id:
                    continue
                # Prompt for parameters if needed
                doc_desc = ssm.describe_document(Name=doc_name)
                params = doc_desc.get('Document', {}).get('Parameters', [])
                param_values = {}
                for param in params:
                    key = param['Name']
                    default = param.get('DefaultValue', "")
                    desc = param.get('Description', "")
                    prompt = f"Enter value for {key} ({desc})"
                    value = Prompt.ask(prompt, default=default)
                    param_values[key] = [value]
                # Run the document
                try:
                    response = ssm.send_command(
                        InstanceIds=[instance_id],
                        DocumentName=doc_name,
                        Parameters=param_values if param_values else {},
                    )
                    command_id = response['Command']['CommandId']
                    import time
                    for _ in range(30):
                        time.sleep(2)
                        output = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
                        if output['Status'] in ('Success', 'Failed', 'Cancelled', 'TimedOut'):
                            break
                    console.print(Panel(f"[bold]Command Output:[/bold]\n{output.get('StandardOutputContent', '').strip()}", title="SSM Output"))
                    if output.get('StandardErrorContent'):
                        console.print(Panel(f"[red]{output['StandardErrorContent']}[/red]", title="SSM Error"))
                except Exception as e:
                    console.print(f"[red]Error running SSM document: {e}[/red]")
            except Exception as e:
                console.print(f"[red]Error fetching SSM documents: {e}[/red]")
        choice = questionary.select("Select an option:", choices=menu).ask()

        if choice == "List EC2 instances":
            instances = get_instances(profile, region)
            if not instances:
                console.print("[red]No instances found.[/red]")
            else:
                display_instances(instances)
        elif choice == "Start/Stop an instance":
            instances = get_instances(profile, region)
            if not instances:
                console.print("[red]No instances found.[/red]")
                continue
            inst = select_instance(instances)
            action = Prompt.ask(f"Action for [cyan]{inst.id}[/cyan]", choices=["start", "stop", "cancel"])
            if action == "start":
                inst.start()
                console.print(f"[green]Started {inst.id}[/green]")
            elif action == "stop":
                inst.stop()
                console.print(f"[yellow]Stopped {inst.id}[/yellow]")
            else:
                continue
        elif choice == "View instance details":
            instances = get_instances(profile, region)
            if not instances:
                console.print("[red]No instances found.[/red]")
                continue
            inst = pick_instance_interactive(instances)
            if not inst:
                console.print("[yellow]No instance selected.[/yellow]")
                continue
            # Gather details
            name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
            state = inst.state['Name']
            private_ip = getattr(inst, 'private_ip_address', '-')
            info_table = Table(title=f"Instance Info: {inst.id}", box=box.ROUNDED)
            info_table.add_column("Field", style="cyan", no_wrap=True)
            info_table.add_column("Value", style="green")
            info_table.add_row("Instance ID", inst.id)
            info_table.add_row("Name", name)
            info_table.add_row("State", state)
            info_table.add_row("Private IP", str(private_ip))
            console.print(info_table)
        elif choice == "View/Edit instance tags":
            # View/Edit instance tags with selectable menu
            instances = get_instances(profile, region)
            if not instances:
                console.print("[red]No instances found.[/red]")
                continue
            # Use questionary to select instance by ID and Name
            instance_choices = []
            for inst in instances:
                name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
                label = f"{inst.id} | {name}"
                instance_choices.append(questionary.Choice(title=label, value=inst))
            inst = questionary.select("Select an instance to edit tags:", choices=instance_choices).ask()
            if not inst:
                continue
            tags = inst.tags or []
            if not tags:
                console.print("[yellow]No tags found for this instance.[/yellow]")
                continue
            tag_choices = [questionary.Choice(title=f"{tag['Key']} = {tag['Value']}", value=tag['Key']) for tag in tags]
            tag_choices.append(questionary.Choice(title="Cancel", value="cancel"))
            tag_to_edit = questionary.select("Select tag key to edit:", choices=tag_choices).ask()
            if tag_to_edit == 'cancel':
                continue
            new_value = Prompt.ask(f"Enter new value for tag '{tag_to_edit}'")
            # Update tag
            inst.create_tags(Tags=[{'Key': tag_to_edit, 'Value': new_value}])
            console.print(f"[green]Tag '{tag_to_edit}' updated![/green]")
        elif choice == "Instance Lookup":
            # ...existing code...
            while True:
                instances = get_instances(profile, region)
                if not instances:
                    console.print("[red]No instances found.[/red]")
                    break
                lookup_menu = [
                    "By InstanceID",
                    "By Name",
                    "By Private IP",
                    "Back"
                ]
                for i, item in enumerate(lookup_menu, 1):
                    console.print(f"[bold]{i}.[/bold] {item}")
                lookup_choice = Prompt.ask("Lookup by", choices=[str(i) for i in range(1, len(lookup_menu)+1)])
                found_matches = []
                if lookup_choice == "1":
                    search = Prompt.ask("Enter (partial) InstanceID to search for")
                    found_matches = [inst for inst in instances if search.lower() in inst.id.lower()]
                elif lookup_choice == "2":
                    search = Prompt.ask("Enter (partial) Name to search for")
                    found_matches = [inst for inst in instances if search.lower() in (next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "").lower())]
                elif lookup_choice == "3":
                    search = Prompt.ask("Enter (partial) Private IP to search for")
                    found_matches = [inst for inst in instances if search in str(getattr(inst, 'private_ip_address', '') or '')]
                elif lookup_choice == "4":
                    break
                if found_matches:
                    # Use questionary to select from matches if more than one
                    if len(found_matches) == 1:
                        found = found_matches[0]
                    else:
                        choices = []
                        for inst in found_matches:
                            name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
                            label = f"{inst.id} | {name} | {inst.state['Name']} | {getattr(inst, 'private_ip_address', '-') or '-'}"
                            choices.append(questionary.Choice(title=label, value=inst))
                        found = questionary.select("Select an instance:", choices=choices).ask()
                    if found:
                        name = next((t['Value'] for t in found.tags or [] if t['Key'] == 'Name'), "-")
                        state = found.state['Name']
                        private_ip = getattr(found, 'private_ip_address', '-')
                        info_table = Table(title=f"Instance Info: {found.id}", box=box.ROUNDED)
                        info_table.add_column("Field", style="cyan", no_wrap=True)
                        info_table.add_column("Value", style="green")
                        info_table.add_row("Instance ID", found.id)
                        info_table.add_row("Name", name)
                        info_table.add_row("State", state)
                        info_table.add_row("Private IP", str(private_ip))
                        console.print(info_table)
                    else:
                        console.print("[yellow]No instance selected.[/yellow]")
                else:
                    console.print("[yellow]No matching instance found.[/yellow]")
                    try_another = questionary.confirm("Would you like to try another AWS SSO profile?").ask()
                    if try_another:
                        # List available profiles
                        import configparser, os
                        aws_config = os.path.expanduser('~/.aws/config')
                        config = configparser.ConfigParser()
                        config.read(aws_config)
                        profiles = [s.replace('profile ', '') for s in config.sections() if s.startswith('profile ')]
                        new_profile = questionary.select("Select AWS profile:", choices=profiles).ask()
                        if new_profile:
                            ensure_sso_login(new_profile)
                            # Optionally prompt for region again
                            session = boto3.Session(profile_name=new_profile)
                            ec2 = session.client('ec2')
                            regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
                            new_region = questionary.select("Select AWS region:", choices=regions).ask()
                            if new_region:
                                profile = new_profile
                                region = new_region
                                continue  # repeat the same search with new profile/region
                    break
        elif choice == "Run Shell Command (SSM)":
            instances = get_instances(profile, region)
            if not instances:
                console.print("[red]No instances found.[/red]")
                continue
            session = boto3.Session(profile_name=profile, region_name=region)
            ssm = session.client('ssm')
            try:
                ssm_instance_ids = set()
                paginator = ssm.get_paginator('describe_instance_information')
                for page in paginator.paginate():
                    infos = page.get('InstanceInformationList', [])
                    ssm_instance_ids.update(info['InstanceId'] for info in infos)
            except Exception as e:
                console.print(f"[red]Error fetching SSM info: {e}[/red]")
                continue
            # New submenu for SSM command scope
            ssm_menu = [
                "Run on Specific Instance",
                "Run on ALL Instances",
                "Cancel"
            ]
            ssm_choice = questionary.select("Choose SSM command scope:", choices=ssm_menu).ask()
            if ssm_choice == "Cancel":
                continue
            shell_cmd = Prompt.ask("Enter shell command to run (e.g. 'uptime')")
            if ssm_choice == "Run on Specific Instance":
                instance_choices = []
                for inst in instances:
                    name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
                    if inst.id in ssm_instance_ids:
                        label = f"{inst.id} | {name}"
                        instance_choices.append(questionary.Choice(title=label, value=inst.id))
                    else:
                        label = f"{inst.id} | {name} [Not SSM-Enabled]"
                        instance_choices.append(questionary.Choice(title=label, value=None, disabled="Not SSM-Enabled"))
                instance_id = questionary.select("Select an instance to run a shell command:", choices=instance_choices).ask()
                if not instance_id:
                    continue
                try:
                    response = ssm.send_command(
                        InstanceIds=[instance_id],
                        DocumentName="AWS-RunShellScript",
                        Parameters={"commands": [shell_cmd]},
                    )
                    command_id = response['Command']['CommandId']
                    # Wait for command to finish
                    import time
                    for _ in range(30):
                        time.sleep(2)
                        output = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
                        if output['Status'] in ('Success', 'Failed', 'Cancelled', 'TimedOut'):
                            break
                    console.print(Panel(f"[bold]Command Output:[/bold]\n{output.get('StandardOutputContent', '').strip()}", title="SSM Output"))
                    if output.get('StandardErrorContent'):
                        console.print(Panel(f"[red]{output['StandardErrorContent']}[/red]", title="SSM Error"))
                except Exception as e:
                    console.print(f"[red]Error running SSM command: {e}[/red]")
            elif ssm_choice == "Run on ALL Instances":
                enabled_instance_ids = [inst.id for inst in instances if inst.id in ssm_instance_ids]
                if not enabled_instance_ids:
                    console.print("[yellow]No SSM-enabled instances found.[/yellow]")
                    continue
                # SSM SendCommand has a max of 50 instance IDs per call
                import math
                try:
                    chunk_size = 50
                    for i in range(0, len(enabled_instance_ids), chunk_size):
                        chunk = enabled_instance_ids[i:i+chunk_size]
                        response = ssm.send_command(
                            InstanceIds=chunk,
                            DocumentName="AWS-RunShellScript",
                            Parameters={"commands": [shell_cmd]},
                        )
                        command_id = response['Command']['CommandId']
                        import time
                        # Wait for all invocations in this chunk to finish
                        for instance_id in chunk:
                            for _ in range(30):
                                time.sleep(2)
                                output = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
                                if output['Status'] in ('Success', 'Failed', 'Cancelled', 'TimedOut'):
                                    break
                            console.print(Panel(f"[bold]Instance {instance_id} Output:[/bold]\n{output.get('StandardOutputContent', '').strip()}", title=f"SSM Output: {instance_id}"))
                            if output.get('StandardErrorContent'):
                                console.print(Panel(f"[red]{output['StandardErrorContent']}[/red]", title=f"SSM Error: {instance_id}"))
                except Exception as e:
                    console.print(f"[red]Error running SSM command on all instances: {e}[/red]")

        if choice == "List EC2 instances":
            instances = get_instances(profile, region)
            if not instances:
                console.print("[red]No instances found.[/red]")
            else:
                display_instances(instances)
        elif choice == "Start/Stop an instance":
            instances = get_instances(profile, region)
            if not instances:
                console.print("[red]No instances found.[/red]")
                continue
            inst = select_instance(instances)
            action = Prompt.ask(f"Action for [cyan]{inst.id}[/cyan]", choices=["start", "stop", "cancel"])
            if action == "start":
                inst.start()
                console.print(f"[green]Started {inst.id}[/green]")
            elif action == "stop":
                inst.stop()
                console.print(f"[yellow]Stopped {inst.id}[/yellow]")
            else:
                continue
        elif choice == "View instance details":
            instances = get_instances(profile, region)
            if not instances:
                console.print("[red]No instances found.[/red]")
                continue
            inst = pick_instance_interactive(instances)
            if not inst:
                console.print("[yellow]No instance selected.[/yellow]")
                continue
            # Gather details
            name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
            state = inst.state['Name']
            private_ip = getattr(inst, 'private_ip_address', '-')
            info_table = Table(title=f"Instance Info: {inst.id}", box=box.ROUNDED)
            info_table.add_column("Field", style="cyan", no_wrap=True)
            info_table.add_column("Value", style="green")
            info_table.add_row("Instance ID", inst.id)
            info_table.add_row("Name", name)
            info_table.add_row("State", state)
            info_table.add_row("Private IP", str(private_ip))
            console.print(info_table)
        elif choice == "View/Edit instance tags":
            # View/Edit instance tags with selectable menu
            instances = get_instances(profile, region)
            if not instances:
                console.print("[red]No instances found.[/red]")
                continue
            # Use questionary to select instance by ID and Name
            instance_choices = []
            for inst in instances:
                name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
                label = f"{inst.id} | {name}"
                instance_choices.append(questionary.Choice(title=label, value=inst))
            inst = questionary.select("Select an instance to edit tags:", choices=instance_choices).ask()
            if not inst:
                continue
            tags = inst.tags or []
            if not tags:
                console.print("[yellow]No tags found for this instance.[/yellow]")
                continue
            tag_choices = [questionary.Choice(title=f"{tag['Key']} = {tag['Value']}", value=tag['Key']) for tag in tags]
            tag_choices.append(questionary.Choice(title="Cancel", value="cancel"))
            tag_to_edit = questionary.select("Select tag key to edit:", choices=tag_choices).ask()
            if tag_to_edit == 'cancel':
                continue
            new_value = Prompt.ask(f"Enter new value for tag '{tag_to_edit}'")
            # Update tag
            inst.create_tags(Tags=[{'Key': tag_to_edit, 'Value': new_value}])
            console.print(f"[green]Tag '{tag_to_edit}' updated![/green]")
        elif choice == "Instance Lookup":
            # Instance Lookup with partial match and free input
            while True:
                instances = get_instances(profile, region)
                if not instances:
                    console.print("[red]No instances found.[/red]")
                    break
                lookup_menu = [
                    "By InstanceID",
                    "By Name",
                    "By Private IP",
                    "Back"
                ]
                for i, item in enumerate(lookup_menu, 1):
                    console.print(f"[bold]{i}.[/bold] {item}")
                lookup_choice = Prompt.ask("Lookup by", choices=[str(i) for i in range(1, len(lookup_menu)+1)])
                found_matches = []
                if lookup_choice == "1":
                    search = Prompt.ask("Enter (partial) InstanceID to search for")
                    found_matches = [inst for inst in instances if search.lower() in inst.id.lower()]
                elif lookup_choice == "2":
                    search = Prompt.ask("Enter (partial) Name to search for")
                    found_matches = [inst for inst in instances if search.lower() in (next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "").lower())]
                elif lookup_choice == "3":
                    search = Prompt.ask("Enter (partial) Private IP to search for")
                    found_matches = [inst for inst in instances if search in str(getattr(inst, 'private_ip_address', '') or '')]
                elif lookup_choice == "4":
                    break
                if found_matches:
                    # Use questionary to select from matches if more than one
                    if len(found_matches) == 1:
                        found = found_matches[0]
                    else:
                        choices = []
                        for inst in found_matches:
                            name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
                            label = f"{inst.id} | {name} | {inst.state['Name']} | {getattr(inst, 'private_ip_address', '-') or '-'}"
                            choices.append(questionary.Choice(title=label, value=inst))
                        found = questionary.select("Select an instance:", choices=choices).ask()
                    if found:
                        name = next((t['Value'] for t in found.tags or [] if t['Key'] == 'Name'), "-")
                        state = found.state['Name']
                        private_ip = getattr(found, 'private_ip_address', '-')
                        info_table = Table(title=f"Instance Info: {found.id}", box=box.ROUNDED)
                        info_table.add_column("Field", style="cyan", no_wrap=True)
                        info_table.add_column("Value", style="green")
                        info_table.add_row("Instance ID", found.id)
                        info_table.add_row("Name", name)
                        info_table.add_row("State", state)
                        info_table.add_row("Private IP", str(private_ip))
                        console.print(info_table)
                    else:
                        console.print("[yellow]No instance selected.[/yellow]")
                else:
                    console.print("[yellow]No matching instance found.[/yellow]")
                    try_another = questionary.confirm("Would you like to try another AWS SSO profile?").ask()
                    if try_another:
                        # List available profiles
                        import configparser, os
                        aws_config = os.path.expanduser('~/.aws/config')
                        config = configparser.ConfigParser()
                        config.read(aws_config)
                        profiles = [s.replace('profile ', '') for s in config.sections() if s.startswith('profile ')]
                        new_profile = questionary.select("Select AWS profile:", choices=profiles).ask()
                        if new_profile:
                            ensure_sso_login(new_profile)
                            # Optionally prompt for region again
                            session = boto3.Session(profile_name=new_profile)
                            ec2 = session.client('ec2')
                            regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
                            new_region = questionary.select("Select AWS region:", choices=regions).ask()
                            if new_region:
                                profile = new_profile
                                region = new_region
                                continue  # repeat the same search with new profile/region
                    break
        elif choice == "Switch Profile":
            import configparser, os
            aws_config = os.path.expanduser('~/.aws/config')
            config = configparser.ConfigParser()
            config.read(aws_config)
            profiles = [s.replace('profile ', '') for s in config.sections() if s.startswith('profile ')]
            new_profile = questionary.select("Select AWS profile:", choices=profiles).ask()
            if new_profile:
                ensure_sso_login(new_profile)
                # Prompt for region
                session = boto3.Session(profile_name=new_profile)
                ec2 = session.client('ec2')
                regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
                new_region = questionary.select("Select AWS region:", choices=regions).ask()
                if new_region:
                    profile = new_profile
                    region = new_region
        elif choice == "Exit":
            console.print("[bold green]Goodbye![/bold green]")
            break

if __name__ == "__main__":
    cli()
