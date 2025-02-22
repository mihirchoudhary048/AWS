import boto3
import datetime
import xlsxwriter

ce_client = boto3.client('ce')

# -----------------------------
# 1) DETERMINE LAST 3 MONTHS
# -----------------------------
months = []
today = datetime.date.today()

for i in range(3):
    first_day = (today.replace(day=1) - datetime.timedelta(days=30 * i)).replace(day=1)
    last_day = first_day.replace(day=28) + datetime.timedelta(days=4)
    last_day = last_day - datetime.timedelta(days=last_day.day)
    month_name = first_day.strftime('%b_%Y')  # Replace spaces with underscores
    months.append((first_day.strftime('%Y-%m-%d'), last_day.strftime('%Y-%m-%d'), month_name))

# -----------------------------
# 2) FETCH AWS COST DATA
# -----------------------------
def get_aws_cost(start_date, end_date):
    """
    Fetch AWS cost data for the given time period.
    Returns (total_cost, cost_data_list).
    """
    response = ce_client.get_cost_and_usage(
        TimePeriod={'Start': start_date, 'End': end_date},
        Granularity='MONTHLY',
        Metrics=['UnblendedCost'],
        GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
    )

    cost_data = []
    total_cost = 0.0
    # There's only one ResultsByTime element because Granularity=MONTHLY
    for group in response['ResultsByTime'][0]['Groups']:
        service_name = group['Keys'][0]
        cost = round(float(group['Metrics']['UnblendedCost']['Amount']), 2)
        total_cost += cost
        cost_data.append({'Service': service_name, 'Cost (USD)': cost})

    # Add total cost row
    cost_data.append({'Service': 'Total', 'Cost (USD)': total_cost})

    return total_cost, cost_data

# -----------------------------
# 3) WRITE COST BREAKDOWN SHEET
# -----------------------------
def write_month_sheet(workbook, month, records):
    """
    Create a worksheet for the given month with cost data and an embedded chart.
    """
    # Create a new sheet named after the month (e.g., Feb_2025)
    worksheet = workbook.add_worksheet(month)
    bold = workbook.add_format({'bold': True})

    # Write headers
    worksheet.write(0, 0, 'Service', bold)
    worksheet.write(0, 1, 'Cost (USD)', bold)

    # Write data rows
    for row_num, record in enumerate(records, start=1):
        worksheet.write(row_num, 0, record['Service'])
        worksheet.write(row_num, 1, record['Cost (USD)'])

    # Create a column chart
    chart = workbook.add_chart({'type': 'column'})
    # Exclude the final 'Total' row from the chart (so records-1)
    # Because row_num started at 1, the last row is 'len(records)'
    # So the data range for categories & values is rows 1 to (len(records)-1)
    chart.add_series({
        'categories': [month, 1, 0, len(records)-2, 0],  # A2:A(Last - 1)
        'values':     [month, 1, 1, len(records)-2, 1],  # B2:B(Last - 1)
        'name':       f'{month} Cost Breakdown',
    })
    chart.set_title({'name': f'AWS Cost Breakdown - {month}'})
    chart.set_x_axis({'name': 'Service'})
    chart.set_y_axis({'name': 'Cost (USD)'})

    # Insert chart in cell D2
    worksheet.insert_chart('D2', chart)

# -----------------------------
# 4) SUGGEST COST OPTIMIZATION
# -----------------------------
def suggest_cost_optimization(cost_data):
    """
    Provide cost optimization suggestions for each month's data.
    """
    suggestions = []
    for month, records in cost_data.items():
        for record in records:
            service = record['Service']
            cost = record['Cost (USD)']

            # High-cost threshold (example: >$100)
            if cost > 100 and service.lower() != 'total':
                suggestions.append([month, service,
                    f"Consider rightsizing or optimizing {service} (${cost})"])
            # Zero-cost service
            elif cost == 0 and service.lower() != 'total':
                suggestions.append([month, service,
                    f"Check if {service} is still needed as it has no cost"])
    return suggestions

# -----------------------------
# 5) WRITE SUGGESTIONS SHEET
# -----------------------------
def write_suggestions_sheet(workbook, suggestions):
    """
    Write the cost optimization suggestions to a separate sheet.
    """
    worksheet = workbook.add_worksheet('Optimization_Suggestions')
    bold = workbook.add_format({'bold': True})

    # Write headers
    worksheet.write(0, 0, 'Month', bold)
    worksheet.write(0, 1, 'Service', bold)
    worksheet.write(0, 2, 'Suggestion', bold)

    # Write suggestions
    for row_num, row_data in enumerate(suggestions, start=1):
        worksheet.write(row_num, 0, row_data[0])
        worksheet.write(row_num, 1, row_data[1])
        worksheet.write(row_num, 2, row_data[2])

# -----------------------------
# 6) MAIN LOGIC
# -----------------------------
def main():
    print("🔍 Fetching AWS Cost Data for the last 3 months...")
    cost_data = {}  # { 'Feb_2025': [ {...}, {...} ], 'Jan_2025': [...] }
    for start, end, month_name in months:
        print(f"Fetching data for {month_name} ({start} to {end})...")
        total_cost, records = get_aws_cost(start, end)
        cost_data[month_name] = records
        print(f"💰 Total Cost for {month_name}: ${total_cost:.2f}")

    # Create the workbook once
    filename = "aws_cost_report.xlsx"
    workbook = xlsxwriter.Workbook(filename)

    # Write sheets for each month
    for month_name, records in cost_data.items():
        write_month_sheet(workbook, month_name, records)

    # Generate suggestions and write to a new sheet
    suggestions = suggest_cost_optimization(cost_data)
    write_suggestions_sheet(workbook, suggestions)

    # Close the workbook
    workbook.close()

    print(f"📊 Cost report saved as {filename}")
    print("✅ Report generation completed!")

# -----------------------------
# 7) ENTRY POINT
# -----------------------------
if __name__ == "__main__":
    main()
