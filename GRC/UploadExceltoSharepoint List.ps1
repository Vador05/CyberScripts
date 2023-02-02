#Created Using ChatGPT
# Load the SharePoint snap-in for PowerShell
Add-PSSnapin Microsoft.SharePoint.PowerShell

# Variables for the Excel file and the SharePoint list
$excelFile = "C:\path\to\excel\file.xlsx"
$sharePointSite = "https://your-sharepoint-site.com"
$listName = "ListName"

# Load the data from the Excel file
$excel = New-Object -ComObject "Excel.Application"
$workbook = $excel.Workbooks.Open($excelFile)
$sheet = $workbook.Worksheets.Item(1)
$usedRange = $sheet.UsedRange

# Connect to the SharePoint site
$web = Get-SPWeb $sharePointSite
$list = $web.Lists[$listName]

# Get the columns from the Excel file and the SharePoint list
$excelColumns = $usedRange.Rows[1].Columns | ForEach-Object { $_.Text }
$listColumns = $list.Fields | Where-Object { !$_.Hidden } | Select-Object -ExpandProperty Title

# Loop through each row of the Excel data
for ($row = 2; $row -le $usedRange.Rows.Count; $row++) {
  $item = $list.AddItem()
  $excelRow = $usedRange.Rows.Item($row)

  # Loop through each column of the Excel data and update the corresponding field in the SharePoint list
  for ($col = 1; $col -le $excelColumns.Count; $col++) {
    $excelColumn = $excelColumns[$col - 1]
    $excelValue = $excelRow.Columns.Item($col).Text

    # If the Excel column exists in the SharePoint list, update the corresponding field
    if ($listColumns -contains $excelColumn) {
      $item[$excelColumn] = $excelValue
    }
  }

  # Update the item in the SharePoint list
  $item.Update()
}

# Clean up the Excel object
$workbook.Close()
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($sheet)
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbook)
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel)

# Disconnect from the SharePoint site
$web.Dispose()
