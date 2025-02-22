# 🚀 AWS Inventory Automation with Python 🖥️📊  

📌 **Automate AWS Inventory Collection & Generate Detailed Excel Reports** using **Python & Boto3**  

🔹 **No more manual AWS CLI commands!** These scripts **fetch AWS resource details** and generate structured **Excel reports** in minutes.  
🔹 **Ideal for DevOps, Cloud Engineers, and IT Admins** managing AWS environments.

---

## 📂 **Included Scripts & Features**
| 🚀 Script Name | 🛠️ Description |
|--------------|---------------------------|
| `aws_list_s3.py` | Lists **all S3 Buckets** and exports them to Excel |
| `aws_inventory_report.py` | **Basic AWS Inventory** (EC2, S3, IAM, RDS) to Excel |
| `aws_inventory_advance_report.py` | **Full AWS Tenancy Report** (EC2, VPCs, Security Groups, S3, IAM, RDS, Route 53, CloudFront, Cost Report) |

📌 **Generated Reports (Excel)**  
✔️ `aws_inventory_report.xlsx` → **Basic AWS Inventory**  
✔️ `aws_inventory_advance_report.xlsx` → **Advanced AWS Inventory**  
✔️ `s3_buckets_list.xlsx` → **S3 Bucket List Report**  

---

## 🔧 **Installation & Setup**
🚀 **1️⃣ Clone the Repository**
git clone https://github.com/mihirchoudhary048/OCI-Cloud.git
cd OCI-Cloud/AWS scripts
🚀 2️⃣ Install Required Packages


pip install boto3 pandas openpyxl
🚀 3️⃣ Run the Scripts

Command	Description
python aws_list_s3.py	📂 Fetch & List all S3 Buckets
python aws_inventory_report.py	🖥️ Generate Basic AWS Inventory Report (EC2, S3, IAM, RDS)
python aws_inventory_advance_report.py	🌍 Full AWS Tenancy Report with Security Groups, VPCs, CloudFront
🚀 4️⃣ Download Reports from AWS CloudShell
📌 If using AWS CloudShell, download the Excel reports:

Click → Actions → Download File
Enter filename → aws_inventory_report.xlsx
Save it locally 📂
📊 Sample Excel Report Preview
Instance ID	Type	State	Public IP	Private IP	Launch Time
i-12345678	t2.micro	running	52.1.1.1	192.168.1.1	2024-02-15
📌 Generated Excel reports contain separate sheets for:
✔️ EC2 Instances
✔️ VPCs & Security Groups
✔️ S3 Buckets & IAM Users
✔️ Route 53, CloudFront, and AWS Cost Report

🔥 Why Use This?
✅ Save Time – No more manual AWS CLI commands
✅ Structured Reports – Well-formatted Excel reports
✅ Security & Cost Insights – Identify AWS resources, security gaps, & cost breakdown
✅ Works on AWS CloudShell – No local setup required

🚀 Next Steps
📌 Want to take it further? Try:
✅ Automating this with AWS Lambda
✅ Scheduling it using AWS EventBridge
✅ Emailing reports via AWS SES

📌 💙 Like & ⭐ Star this repository if you find it useful!
📌 📢 Share your feedback or improvements in the Issues section!

🚀 Happy Cloud Automation! ☁️✨

--

