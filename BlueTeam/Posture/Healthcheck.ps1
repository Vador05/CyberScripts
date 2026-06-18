# Define the input and output file paths
$inputFile = "urls.txt"
$outputFile = "results.csv"

# Create an array to store the results
$results = @()

# Read the URLs from the input file
$urls = Get-Content $inputFile

# Iterate over each URL
foreach ($url in $urls) {
    # Create a new object to store the URL and response code
    $result = [PSCustomObject]@{
        URL = $url
        ResponseCode = $null
        DestinationURL = $null
    }

   
    #add the connetion method in case the string does not contain it by default
    if ($url.Contains("http://")){
        $url = $url.Replace('http://','https://') 
    }elseif($url -notcontains("https://")){
      $url = "https://$url"
    }
   
    # Create a new HTTP request
    $request = [System.Net.HttpWebRequest]::Create("$url")
    $request.Method = "HEAD"
    $request.AllowAutoRedirect = $false

    try {
        # Send the HTTP request and get the response
        $response = $request.GetResponse()
        $result.ResponseCode = [int]$response.StatusCode

        # If it's a 302 or 301 redirect, get the destination URL
        if ($response.StatusCode -eq [System.Net.HttpStatusCode]::Found -or
            $response.StatusCode -eq [System.Net.HttpStatusCode]::MovedPermanently) {
            $result.DestinationURL = $response.Headers["Location"]
        }

        # Close the response
        $response.Close()
    }
    catch {
        # If an exception occurs, set the response code to the error message
        $result.ResponseCode = $_.Exception.Message
    }

    # Add the result to the results array
    $results += $result
}

# Export the results to a CSV file
$results | Export-Csv -Path $outputFile -NoTypeInformation