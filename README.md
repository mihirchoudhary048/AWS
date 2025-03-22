# 🚀 AWS Inventory & Health Check Automation with Python 📊 ☁️

Automate **AWS Inventory Collection, Security Audits, and Health Checks** using Python & Boto3.

✅ **No more manual AWS CLI commands!**  
✅ **Auto-generate structured Excel reports for deep insights**  
✅ **Identify security gaps, misconfigurations, and cost insights in minutes**  

Ideal for **DevOps, Cloud Engineers, and IT Admins** managing AWS environments.

---

## 📌 Included Scripts & Features

| Script Name                     | Description |
|----------------------------------|-------------|
| `aws_list_s3.py`                | Lists all **S3 Buckets** and exports details to Excel |
| `aws_inventory_report.py`        | **Basic AWS Inventory** (EC2, S3, IAM, RDS) to Excel |
| `aws_inventory_advance_report.py` | **Full AWS Tenancy Report** (EC2, VPCs, Security Groups, S3, IAM, RDS, Route 53, CloudFront, Cost Insights) |
| `aws_health_check.py`           | **AWS Health Check** (EC2, RDS, Lambda, ELB, S3, CloudWatch alarms) |
| `aws_security_group_auditor.py` | **Security Group Auditor** - Detects open ports and insecure rules |
| `aws_budget_alert.py`           | **AWS Cost & Budget Alerts** - Monitors cloud spending |
| `aws_find_orphan_resources.py`  | **aws_find_orphan_resources.py** - Quickly identifies orphaned or unused AWS resources across your entire AWS account, |
  
---

## 📊 Generated Reports (Excel)
| Report Name                      | Description |
|-----------------------------------|-------------|
| `aws_inventory_report.xlsx`       | **Basic AWS Inventory Report** |
| `aws_inventory_advance_report.xlsx` | **Advanced AWS Inventory Report (Multi-Service)** |
| `s3_buckets_list.xlsx`            | **S3 Bucket List Report** |
| `aws_health_report.xlsx`          | **AWS Health & Performance Report** |
| `aws_security_group_findings.xlsx` | **Security Group & Firewall Audit Report** |
| `aws_cost_report.xlsx`            | **AWS Cost Optimization & Budget Report** |
| `aws_find_orphan_resources.xlsx`  | **orphaned_resources_report** |

---

## 🚀 Installation & Setup

### **1️⃣ Clone the Repository**
```bash
git clone https://github.com/mihirchoudhary048/AWS.git
cd AWS
```

### **2️⃣ Install Required Packages**
```bash
pip install boto3 pandas openpyxl
```

### **3️⃣ Configure AWS Credentials (if not already configured)**
```bash
aws configure
```
Ensure you have permissions to access **EC2, S3, IAM, RDS, ELB, CloudWatch, and Cost Explorer**.

---

## 🐝 How to Run the Scripts

| Command | Description |
|---------|-------------|
| `python aws_list_s3.py` | 📂 Fetch & List all **S3 Buckets** |
| `python aws_inventory_report.py` | 🖥️ Generate **Basic AWS Inventory Report** |
| `python aws_inventory_advance_report.py` | 🏢 Generate **Full AWS Tenancy Report** |
| `python aws_health_check.py` | ❤️‍🔥 Perform **AWS Health Check** (EC2, RDS, Lambda, S3, ELB, CloudWatch) |
| `python aws_security_group_auditor.py` | 🔥 **Security Group & Firewall Rule Audit** |
| `python aws_budget_alert.py` | 💰 **AWS Cost Monitoring & Budget Alert** |

---

## 🔥 Why Use This?
✔ **Save Time** – No more manual AWS CLI commands!  
✔ **Structured Reports** – Well-formatted **Excel reports**  
✔ **Security & Cost Insights** – Identify AWS **security gaps**, **cost breakdowns**, and **overprovisioned resources**  
✔ **Works on AWS CloudShell** – No local setup required  

---

## 🎯 Next Steps & Future Enhancements

💡 Want to take it further? Try:
- **🔄 Automating this with AWS Lambda**
- **⏳ Scheduling it using AWS EventBridge**
- **📧 Emailing reports via SES**
- **📄 Uploading reports to S3 for team access**
- **⚡️ Integrating with AWS Security Hub for compliance monitoring**

---

## ⭐ Support & Contributions
If you find this useful, **please ⭐ star this repository** and share your feedback in the Issues section!

📝 Feel free to **fork and contribute** to improve the scripts!

---

🚀 **Happy Cloud Automation!** ⛈️ 🔥

