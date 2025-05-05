chcp 949
echo 작업 전의 dir 결과
dir
echo Moving to D drive
d:

echo Navigating to the root of D drive
cd \

echo Finding the oldest folder in D drive
$oldestFolder = Get-ChildItem -Directory | Sort-Object CreationTime | Select-Object -First 1

echo Oldest folder is $($oldestFolder.FullName)

echo Searching for the largest file in the oldest folder
$largestFile = Get-ChildItem -Path $oldestFolder.FullName -Recurse -File | Sort-Object Length -Descending | Select-Object -First 1

echo Largest file in the oldest folder:
$largestFile.FullName

echo 작업 후의 dir 결과
dir