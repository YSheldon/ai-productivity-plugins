$ErrorActionPreference = "Stop"
$inputJson = [Console]::In.ReadToEnd()
$requestData = $inputJson | ConvertFrom-Json

$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds([Math]::Max(1, [int]$requestData.timeout_seconds))
$request = [System.Net.Http.HttpRequestMessage]::new(
    [System.Net.Http.HttpMethod]::new([string]$requestData.method),
    [Uri]::new([string]$requestData.url)
)

try {
    if ($null -ne $requestData.body_base64) {
        $body = [Convert]::FromBase64String([string]$requestData.body_base64)
        $request.Content = [System.Net.Http.ByteArrayContent]::new($body)
    }
    foreach ($property in $requestData.headers.PSObject.Properties) {
        $name = [string]$property.Name
        $value = [string]$property.Value
        if (-not $request.Headers.TryAddWithoutValidation($name, $value)) {
            if ($null -eq $request.Content) {
                $request.Content = [System.Net.Http.ByteArrayContent]::new([byte[]]::new(0))
            }
            if (-not $request.Content.Headers.TryAddWithoutValidation($name, $value)) {
                throw "Unsupported HTTP header"
            }
        }
    }

    $response = $client.SendAsync($request).GetAwaiter().GetResult()
    try {
        $responseBytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        $headers = @{}
        foreach ($header in $response.Headers) {
            $headers[$header.Key] = [string]::Join(", ", $header.Value)
        }
        foreach ($header in $response.Content.Headers) {
            $headers[$header.Key] = [string]::Join(", ", $header.Value)
        }
        @{
            status = [int]$response.StatusCode
            headers = $headers
            body_base64 = [Convert]::ToBase64String($responseBytes)
        } | ConvertTo-Json -Compress -Depth 6
    }
    finally {
        $response.Dispose()
    }
}
finally {
    $request.Dispose()
    $client.Dispose()
    $handler.Dispose()
}
