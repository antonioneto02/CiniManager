$token = $env:GITHUB_TOKEN
if (-not $token) { Write-Error "GITHUB_TOKEN nao esta definido no ambiente do container"; exit 1 }
$b64 = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("x-access-token:$token"))
& "C:\Program Files\Git\cmd\git.exe" config --global "http.https://github.com/.extraHeader" "AUTHORIZATION: basic $b64"
Write-Output "Git configurado para autenticar no GitHub via GITHUB_TOKEN."
