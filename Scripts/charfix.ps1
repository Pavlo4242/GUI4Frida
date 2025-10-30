Get-ChildItem -Recurse -Filter *.js | ForEach-Object {
    $t = Get-Content $_.FullName -Raw               # read entire file as one string

    # 1️⃣  Replace en‑dash, em‑dash, non‑breaking hyphen  -> plain '-'
    $t = $t -replace '–', '-' `
              -replace '—', '-' `
              -replace '‑', '-' `
    
    # 2️⃣  Replace curly quotation marks  -> straight quotes
    $t = $t -replace '“', '"' `
              -replace '”', '"' `
              -replace '‘', "'" `
              -replace '’', "'"

    Set-Content $_.FullName $t -Encoding utf8        # write back as UTF‑8
    Write-Host "✓  $_.FullName"
}
