
#Originally created with ChatGPT
$ExcelFile = "C:\path\to\excel.xlsx"
$SheetName = "Sheet1"
$PrimaryKeyColumn = "URL"

# Load the Excel assembly
Add-Type -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.dll"
Add-Type -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.Runtime.dll"

# Read the Excel file
$ExcelData = Import-Excel -Path $ExcelFile -SheetName $SheetName

# Connect to SharePoint
$Username = "admin@tenant.onmicrosoft.com"
$Password = ConvertTo-SecureString "Password" -AsPlainText -Force
$Credentials = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($Username, $Password)
$ClientContext = New-Object Microsoft.SharePoint.Client.ClientContext("https://tenant.sharepoint.com/sites/sitename")
$ClientContext.Credentials = $Credentials

# Get the SharePoint list
$List = $ClientContext.Web.Lists.GetByTitle("ListName")
$ClientContext.Load($List)
$ClientContext.ExecuteQuery()

# Loop through each row in the Excel data
foreach ($Row in $ExcelData) {
    # Get the primary key value
    $PrimaryKeyValue = $Row.$PrimaryKeyColumn

    # Check if a list item with the same primary key exists
    $Query = New-Object Microsoft.SharePoint.Client.CamlQuery
    $Query.ViewXml = "<View><Query><Where><Eq><FieldRef Name='$PrimaryKeyColumn'/><Value Type='Text'>$PrimaryKeyValue</Value></Eq></Where></Query></View>"
    $ListItems = $List.GetItems($Query)
    $ClientContext.Load($ListItems)
    $ClientContext.ExecuteQuery()

    # Update the list item if it exists, or create a new list item if it doesn't
    if ($ListItems.Count -eq 1) {
        $ListItem = $ListItems[0]
        foreach ($Property in $Row.PSObject.Properties) {
            if ($Property.Name -ne $PrimaryKeyColumn) {
                $ListItem[$Property.Name] = $Property.Value
            }
        }
        $ListItem.Update()
        $ClientContext.ExecuteQuery()
    } elseif ($ListItems.Count -eq 0) {
        $ListItem = $List.AddItem()
        foreach ($Property in $Row.PSObject.Properties) {
            $ListItem[$Property.Name] = $Property.Value
        }
        $ListItem.Update()
        $ClientContext.ExecuteQuery()
    }
}
