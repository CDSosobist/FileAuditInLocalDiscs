cls
$OUTFOLDER = "\\test-stah01\c`$\users\KoshelevRA\Documents\TEST_FA\"
$SuccesFile = $OUTFOLDER + "success.txt"
$DONTSUCCESSFILE = $OUTFOLDER + "dontSuccess.txt"
Out-File $DONTSUCCESSFILE -Encoding utf8
$Headings = 'Компьютер;Пользователь;Папок в Документах;Файлов в Документах;Размер файлов в документах (Mb);Папок на рабочем столе;Файлов на рабочем столе;Размер файлов на рабочем столе (Mb)'
$OUS = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=ЦДС,OU=Company,OU=CDS,DC=cds,DC=spb" -SearchScope OneLevel
foreach ($OU in $OUS) {
    $OUTFILE = $OUTFOLDER + $OU.Name + ".csv";
    if (((Get-Content $OUTFILE) -eq $null) -or (-not (Test-Path -Path $OUTFILE))) {$Headings | Out-File $OUTFILE -Append utf8}
    $COMPS = Get-ADComputer -Properties lastLogon -Filter * -SearchBase $OU.DistinguishedName;
    foreach ($COMP in $COMPS) {
        $NOTPKB = ($COMP.Name.ToString() -notmatch "PKB")
        $COMPISUP = Test-Connection -ComputerName $COMP.dNSHostName -BufferSize 32 -Count 1 -Quiet
        $IsNotSuccess = $COMP.Name.ToString() -notin (Get-Content $SuccesFile)
        Write-Host $COMP.Name '-' $COMPISUP ', NotPKB -' $NOTPKB ', isNotSuccess - ' $IsNotSuccess
        if ($COMPISUP -And $NOTPKB -And $IsNotSuccess) { 
            $PROFSTRING = '\\' + $COMP.Name.ToString() + '\C$\Users';
            $PROFILES = Get-ChildItem $PROFSTRING -Exclude "Public","tse","User","localuser","yara","monte"
            foreach ($PROFILE in $PROFILES) {
                $TMPCONTROL = Get-ChildItem -LiteralPath ($PROFILE.FullName + "\AppData\Local") -Filter "Temp"
                if ($TMPCONTROL.LastWriteTime -gt ((Get-Date).AddDays(-21))) {
                    $PROFUSERNAME = (Get-ADUser -Identity $PROFILE.Name).Name;
                    Write-Host $PROFILE.FullName.ToString();
                    $DOCSPATH = $PROFILE.FullName.ToString() + "\Documents"; 
                    $DESKTOPPATH = $PROFILE.FullName.ToString() + "\DESKTOP";
                    $FOLDERSINDOCS = (Get-ChildItem $DOCSPATH -Recurse -Directory | Where-Object {$_.LastWriteTime -lt ((Get-Date).AddDays(-21))}).Count
                    $FILEINDOCS = Get-ChildItem $DOCSPATH -Recurse -File | Where-Object {$_.LastWriteTime -lt ((Get-Date).AddDays(-21))}
                    $FILEINDOCSCOUNT = ($FILEINDOCS | Measure-Object).Count
                    $FILEINDOCSSIZE = ($FILEINDOCS | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB
                    $FILEINDOCSSIZE_ROUND = [math]::Round($FILEINDOCSSIZE, 1)
                    Write-Host $FILEINDOCSSIZE_ROUND
                    $FOLDERSINDESKTOP = (Get-ChildItem $DESKTOPPATH -Recurse -Directory | Where-Object {$_.LastWriteTime -lt ((Get-Date).AddDays(-21))} | Measure-Object).Count
                    $FILESINDESKTOP = Get-ChildItem $DESKTOPPATH -Recurse -File | Where-Object {$_.LastWriteTime -lt ((Get-Date).AddDays(-21))}
                    $FILEINDESKTOPCOUNT = ($FILEINDESKTOP | Measure-Object).Count
                    $FILEINDESKTOPSIZE = ($FILEINDESKTOP | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB
                    $FILEINDESKTOPSIZE_ROUND = [math]::Round($FILEINDESKTOPSIZE, 1)
                    $COMP.Name + ';' + $PROFUSERNAME + ';' + $FOLDERSINDOCS + ';' + $FILEINDOCSCOUNT + ';' + $FILEINDOCSSIZE_ROUND + ';' + $FOLDERSINDESKTOP + ';' + $FILEINDESKTOPCOUNT + ';' + $FILEINDESKTOPSIZE_ROUND | Out-File $OUTFILE -Append utf8;
                    $COMP.Name.ToString() | Out-File $SuccesFile -Append utf8;
                }
            }
        }
        $IsSuccess = $COMP.Name.ToString() -in (Get-Content $SuccesFile)
        if ((-not $IsSuccess) -And $NOTPKB) {$COMP.Name + ' - ' + [datetime]::FromFileTime($COMP.lastLogon).ToString('g') | Out-File $DONTSUCCESSFILE -Append utf8}
    }
}