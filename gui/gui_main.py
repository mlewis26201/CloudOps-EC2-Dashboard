import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel, QTableWidget, QTableWidgetItem, QHBoxLayout, QMessageBox, QInputDialog, QComboBox, QLineEdit
from PyQt5.QtCore import Qt
import boto3
import subprocess
import os
import configparser

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CloudOps EC2 Dashboard (GUI)")
        self.setGeometry(100, 100, 900, 600)
        self.profile = None
        self.region = None
        self.session = None
        self.ec2 = None
        self.init_ui()

    def init_ui(self):
        widget = QWidget()
        layout = QVBoxLayout()

        self.profile_btn = QPushButton("Set AWS Profile/Region")
        self.profile_btn.clicked.connect(self.set_profile_region)
        layout.addWidget(self.profile_btn)

        # Search bar and filter
        search_layout = QHBoxLayout()
        self.search_type = QComboBox()
        self.search_type.addItems(["Instance ID", "Name", "Private IP"])
        search_layout.addWidget(QLabel("Search by:"))
        search_layout.addWidget(self.search_type)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search text...")
        search_layout.addWidget(self.search_input)
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.filter_instances)
        search_layout.addWidget(self.search_btn)
        layout.addLayout(search_layout)

        self.refresh_btn = QPushButton("List EC2 Instances")
        self.refresh_btn.clicked.connect(self.list_instances)
        layout.addWidget(self.refresh_btn)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["ID", "State", "Name", "Type"])
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Instance")
        self.start_btn.clicked.connect(lambda: self.instance_action('start'))
        btn_layout.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Stop Instance")
        self.stop_btn.clicked.connect(lambda: self.instance_action('stop'))
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)


        self.ssm_btn = QPushButton("Run SSM Command on Selected")
        self.ssm_btn.clicked.connect(self.run_ssm_command)
        layout.addWidget(self.ssm_btn)

        self.ssm_doc_btn = QPushButton("Run SSM Document (ERApp)")
        self.ssm_doc_btn.clicked.connect(self.run_ssm_document_erapp)
        layout.addWidget(self.ssm_doc_btn)
    def run_ssm_document_erapp(self):
        if not self.ec2:
            QMessageBox.warning(self, "Not Ready", "Set AWS profile and region first.")
            return
        if not self.ensure_sso_login(self.profile):
            return
        try:
            ssm = self.session.client('ssm')
            # Get SSM documents with tag ERApp=true
            paginator = ssm.get_paginator('list_documents')
            docs = []
            for page in paginator.paginate(Filters=[{"Key": "Owner", "Values": ["Self"]}]):
                for doc in page.get('DocumentIdentifiers', []):
                    doc_name = doc['Name']
                    tags = ssm.list_tags_for_resource(ResourceType='Document', ResourceId=doc_name).get('TagList', [])
                    if any(t['Key'] == 'ERApp' and t['Value'] == 'true' for t in tags):
                        docs.append(doc)
            if not docs:
                QMessageBox.information(self, "No SSM Documents", "No SSM documents found with tag ERApp=true.")
                return
            doc_names = [f"{doc['Name']} ({doc['DocumentType']})" for doc in docs]
            doc_map = {f"{doc['Name']} ({doc['DocumentType']})": doc['Name'] for doc in docs}
            doc_choice, ok = self.select_from_list("Select SSM Document", "Choose SSM Document to run:", doc_names)
            if not ok or not doc_choice:
                return
            doc_name = doc_map[doc_choice]
            # Select instance to run on
            instances = list(self.ec2.instances.all())
            if not instances:
                QMessageBox.warning(self, "No Instances", "No EC2 instances found.")
                return
            inst_names = [f"{inst.id} | {next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), '-') }" for inst in instances]
            inst_map = {f"{inst.id} | {next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), '-') }": inst.id for inst in instances}
            inst_choice, ok = self.select_from_list("Select Instance", "Choose instance to run document:", inst_names)
            if not ok or not inst_choice:
                return
            instance_id = inst_map[inst_choice]
            # Prompt for parameters if needed
            doc_desc = ssm.describe_document(Name=doc_name)
            params = doc_desc.get('Document', {}).get('Parameters', [])
            param_values = {}
            for param in params:
                key = param['Name']
                default = param.get('DefaultValue', "")
                desc = param.get('Description', "")
                value, ok = QInputDialog.getText(self, f"Parameter: {key}", f"{desc}\nDefault: {default}")
                if not ok:
                    return
                param_values[key] = [value if value else default]
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
                out = output.get('StandardOutputContent', '').strip()
                err = output.get('StandardErrorContent', '').strip()
                msg = f"Output:\n{out}"
                if err:
                    msg += f"\n\nError:\n{err}"
                QMessageBox.information(self, "SSM Output", msg)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error running SSM document: {e}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error fetching SSM documents: {e}")

        widget.setLayout(layout)
        self.setCentralWidget(widget)
        self.all_instances = []  # Store all instances for filtering

    def ensure_sso_login(self, profile):
        # Try a simple STS call, if it fails, run aws sso login
        try:
            session = boto3.Session(profile_name=profile)
            sts = session.client('sts')
            sts.get_caller_identity()
            return True
        except Exception:
            ret = QMessageBox.question(self, "SSO Login Required", f"SSO session expired or not found for profile '{profile}'.\nRun 'aws sso login'?", QMessageBox.Yes | QMessageBox.No)
            if ret == QMessageBox.Yes:
                try:
                    subprocess.run(["aws", "sso", "login", "--profile", profile], check=True)
                    return True
                except Exception as e:
                    QMessageBox.critical(self, "SSO Login Failed", str(e))
            return False

    def set_profile_region(self):
        # Pull AWS SSO profiles from ~/.aws/config
        aws_config_path = os.path.expanduser('~/.aws/config')
        config = configparser.ConfigParser()
        config.read(aws_config_path)
        profiles = [s.replace('profile ', '') for s in config.sections() if s.startswith('profile ')]
        if not profiles:
            QMessageBox.critical(self, "No Profiles", "No AWS SSO profiles found in ~/.aws/config.")
            return
        # Profile selection dialog
        profile, ok = self.select_from_list("Select AWS Profile", "Choose your AWS SSO profile:", profiles)
        if not ok or not profile:
            return
        # Get regions for this profile
        try:
            session = boto3.Session(profile_name=profile)
            ec2 = session.client('ec2')
            regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
        except Exception:
            # fallback to common regions
            regions = ["us-east-1", "us-west-2", "eu-west-1"]
        region, ok = self.select_from_list("Select AWS Region", "Choose your AWS region:", regions)
        if not ok or not region:
            return
        self.profile = profile
        self.region = region
        if not self.ensure_sso_login(profile):
            return
        try:
            self.session = boto3.Session(profile_name=profile, region_name=region)
            self.ec2 = self.session.resource('ec2')
            QMessageBox.information(self, "Profile Set", f"Profile: {profile}\nRegion: {region}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def select_from_list(self, title, label, items):
        # Simple selection dialog using QInputDialog
        from PyQt5.QtWidgets import QInputDialog
        item, ok = QInputDialog.getItem(self, title, label, items, 0, False)
        return item, ok

    def list_instances(self):
        if not self.ec2:
            QMessageBox.warning(self, "Not Ready", "Set AWS profile and region first.")
            return
        # Ensure SSO login before listing
        if not self.ensure_sso_login(self.profile):
            return
        try:
            instances = list(self.ec2.instances.all())
            self.all_instances = instances  # Save for filtering
            self.display_instances(instances)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def display_instances(self, instances):
        self.table.setRowCount(0)
        for inst in instances:
            row = self.table.rowCount()
            self.table.insertRow(row)
            name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
            self.table.setItem(row, 0, QTableWidgetItem(inst.id))
            self.table.setItem(row, 1, QTableWidgetItem(inst.state['Name']))
            self.table.setItem(row, 2, QTableWidgetItem(name))
            self.table.setItem(row, 3, QTableWidgetItem(inst.instance_type))

    def filter_instances(self):
        # Always refresh the instance list before filtering
        if not self.ec2:
            QMessageBox.warning(self, "Not Ready", "Set AWS profile and region first.")
            return
        if not self.ensure_sso_login(self.profile):
            return
        try:
            # Always get the latest list
            instances = list(self.ec2.instances.all())
            self.all_instances = instances
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return
        search_text = self.search_input.text().strip().lower()
        search_type = self.search_type.currentText()
        if not search_text:
            self.display_instances(self.all_instances)
            return
        filtered = []
        for inst in self.all_instances:
            name = next((t['Value'] for t in inst.tags or [] if t['Key'] == 'Name'), "-")
            private_ip = str(getattr(inst, 'private_ip_address', '') or '')
            if search_type == "Instance ID" and search_text in inst.id.lower():
                filtered.append(inst)
            elif search_type == "Name" and search_text in name.lower():
                filtered.append(inst)
            elif search_type == "Private IP" and search_text in private_ip:
                filtered.append(inst)
        self.display_instances(filtered)

    def get_selected_instance(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        instance_id = self.table.item(row, 0).text()
        return self.ec2.Instance(instance_id)

    def instance_action(self, action):
        inst = self.get_selected_instance()
        if not inst:
            QMessageBox.warning(self, "No Selection", "Select an instance in the table.")
            return
        # Ensure SSO login before action
        if not self.ensure_sso_login(self.profile):
            return
        try:
            if action == 'start':
                inst.start()
                QMessageBox.information(self, "Started", f"Started {inst.id}")
            elif action == 'stop':
                inst.stop()
                QMessageBox.information(self, "Stopped", f"Stopped {inst.id}")
            self.list_instances()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def run_ssm_command(self):
        inst = self.get_selected_instance()
        if not inst:
            QMessageBox.warning(self, "No Selection", "Select an instance in the table.")
            return
        # Ensure SSO login before SSM
        if not self.ensure_sso_login(self.profile):
            return
        cmd, ok = QInputDialog.getText(self, "SSM Command", "Enter shell command to run:")
        if not ok or not cmd:
            return
        try:
            ssm = self.session.client('ssm')
            response = ssm.send_command(
                InstanceIds=[inst.id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [cmd]},
            )
            command_id = response['Command']['CommandId']
            import time
            for _ in range(30):
                time.sleep(2)
                output = ssm.get_command_invocation(CommandId=command_id, InstanceId=inst.id)
                if output['Status'] in ('Success', 'Failed', 'Cancelled', 'TimedOut'):
                    break
            out = output.get('StandardOutputContent', '').strip()
            err = output.get('StandardErrorContent', '').strip()
            msg = f"Output:\n{out}"
            if err:
                msg += f"\n\nError:\n{err}"
            QMessageBox.information(self, "SSM Output", msg)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
