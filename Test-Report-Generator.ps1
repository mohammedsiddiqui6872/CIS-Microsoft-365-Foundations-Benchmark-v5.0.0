# Test Report Generator - Creates a sample HTML report to test new features
# This script generates a report with sample data to test the search box and L1/L2 cards

$outputPath = "C:\Powershell"
$reportPath = Join-Path $outputPath "Test-CIS-Compliance-Report.html"

# Sample test data
$testResults = @(
    [PSCustomObject]@{
        ControlNumber = "1.1.1"
        ControlTitle = "Ensure administrative accounts are cloud-only"
        ProfileLevel = "L1"
        Result = "Pass"
        Details = "No synchronized admin accounts found"
        Remediation = ""
    },
    [PSCustomObject]@{
        ControlNumber = "2.1.1"
        ControlTitle = "Ensure Safe Links for Office Applications is Enabled"
        ProfileLevel = "L1"
        Result = "Fail"
        Details = "Safe Links not configured for all applications"
        Remediation = "Enable Safe Links in Microsoft Defender"
    },
    [PSCustomObject]@{
        ControlNumber = "5.2.3.1"
        ControlTitle = "Ensure Microsoft Authenticator is configured to protect against MFA fatigue"
        ProfileLevel = "L1"
        Result = "Pass"
        Details = "Number matching: enabled, App context: enabled, Location: enabled"
        Remediation = ""
    },
    [PSCustomObject]@{
        ControlNumber = "5.1.5.1"
        ControlTitle = "Ensure user consent to apps accessing company data is not allowed"
        ProfileLevel = "L2"
        Result = "Pass"
        Details = "User consent disabled"
        Remediation = ""
    },
    [PSCustomObject]@{
        ControlNumber = "5.2.2.1"
        ControlTitle = "Ensure multifactor authentication is enabled for all users in administrative roles"
        ProfileLevel = "L1"
        Result = "Manual"
        Details = "Manual verification required"
        Remediation = "Check Entra ID Conditional Access policies"
    },
    [PSCustomObject]@{
        ControlNumber = "6.1.1"
        ControlTitle = "Ensure mailbox auditing for all users is Enabled"
        ProfileLevel = "L1"
        Result = "Pass"
        Details = "Mailbox audit enabled for all users"
        Remediation = ""
    },
    [PSCustomObject]@{
        ControlNumber = "7.2.1"
        ControlTitle = "Ensure external sharing of calendars is not available"
        ProfileLevel = "L2"
        Result = "Fail"
        Details = "External calendar sharing enabled"
        Remediation = "Disable external calendar sharing in SharePoint admin center"
    },
    [PSCustomObject]@{
        ControlNumber = "8.1.1"
        ControlTitle = "Ensure users can't send emails to a channel email address"
        ProfileLevel = "L1"
        Result = "Pass"
        Details = "Channel email is disabled"
        Remediation = ""
    }
)

# Calculate statistics
$totalControls = $testResults.Count
$passedControls = ($testResults | Where-Object { $_.Result -eq "Pass" }).Count
$failedControls = ($testResults | Where-Object { $_.Result -eq "Fail" }).Count
$manualControls = ($testResults | Where-Object { $_.Result -eq "Manual" }).Count
$errorControls = 0

$l1Controls = $testResults | Where-Object { $_.ProfileLevel -eq "L1" }
$l1Total = $l1Controls.Count
$l1Passed = ($l1Controls | Where-Object { $_.Result -eq "Pass" }).Count
$l1Failed = ($l1Controls | Where-Object { $_.Result -eq "Fail" }).Count
$l1Manual = ($l1Controls | Where-Object { $_.Result -eq "Manual" }).Count

$l2Controls = $testResults | Where-Object { $_.ProfileLevel -eq "L2" }
$l2Total = $l2Controls.Count
$l2Passed = ($l2Controls | Where-Object { $_.Result -eq "Pass" }).Count
$l2Failed = ($l2Controls | Where-Object { $_.Result -eq "Fail" }).Count
$l2Manual = ($l2Controls | Where-Object { $_.Result -eq "Manual" }).Count

$passRate = [math]::Round(($passedControls / ($totalControls - $manualControls)) * 100, 2)
$l1PassRate = if (($l1Total - $l1Manual) -gt 0) { [math]::Round(($l1Passed / ($l1Total - $l1Manual)) * 100, 2) } else { 0 }
$l2PassRate = if (($l2Total - $l2Manual) -gt 0) { [math]::Round(($l2Passed / ($l2Total - $l2Manual)) * 100, 2) } else { 0 }

$reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"
$currentUser = $env:USERNAME

# Generate HTML
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>CIS Microsoft 365 Compliance Report - TEST</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #f1f5f9; line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }

        /* Header */
        .header {
            background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 28px; color: white; }
        .subtitle {
            font-size: 0.9em;
            opacity: 0.9;
            margin-top: 4px;
            color: white;
        }
        .header-right { text-align: right; color: #dbeafe; }

        /* Collapsible header details */
        .tenant-info {
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 4px 8px;
            border-radius: 5px;
            transition: background-color 0.3s ease;
        }
        .tenant-info:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        .expand-icon {
            font-size: 0.8em;
            transition: transform 0.3s ease;
        }
        .expand-icon.expanded {
            transform: rotate(180deg);
        }
        .header-details {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
            margin-top: 0;
        }
        .header-details.expanded {
            max-height: 200px;
            margin-top: 10px;
        }

        /* Content */
        .content { padding: 10px 40px 20px 40px; }
        h2 { color: #60a5fa; margin-top: 30px; margin-bottom: 15px; }
        h2:first-child { margin-top: 0; margin-bottom: 10px; }

        .summary { background: #18181b; padding: 12px 15px; border-radius: 8px; margin-bottom: 25px; border: 1px solid #27272a; }

        .summary-box {
            display: inline-block;
            margin: 8px 15px 8px 0;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s ease;
            background-color: #000000;
            border: 2px solid #ffffff;
        }
        .summary-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 8px rgba(255, 255, 255, 0.5);
        }
        .summary-box.active {
            box-shadow: 0 0 12px rgba(96, 165, 250, 0.8);
            border: 2px solid #60a5fa !important;
        }
        .pass { color: #4ade80; }
        .fail { color: #f87171; }
        .manual { color: #fbbf24; }
        .error { color: #f87171; }
        .level-l1 { color: #93c5fd; }
        .level-l2 { color: #c4b5fd; }

        .progress-bar { width: 100%; height: 30px; background-color: #27272a; border-radius: 5px; overflow: hidden; margin: 15px 0; }
        .progress-fill { height: 100%; background-color: #22c55e; text-align: center; line-height: 30px; color: white; font-weight: bold; }

        /* Search Box */
        .search-container {
            position: relative;
            margin: 20px 0;
            max-width: 100%;
        }
        #searchBox {
            width: 100%;
            padding: 15px 50px 15px 20px;
            font-size: 16px;
            background-color: #27272a;
            border: 2px solid #3f3f46;
            border-radius: 8px;
            color: #f4f4f5;
            transition: all 0.3s ease;
            outline: none;
        }
        #searchBox:focus {
            border-color: #60a5fa;
            box-shadow: 0 0 10px rgba(96, 165, 250, 0.3);
        }
        #searchBox::placeholder {
            color: #71717a;
        }
        .search-icon {
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 20px;
            pointer-events: none;
        }
        .search-results {
            display: block;
            margin-top: 8px;
            font-size: 14px;
            color: #a1a1aa;
        }

        table { width: 100%; border-collapse: collapse; background: #18181b; border: 1px solid #27272a; margin-top: 20px; }
        th { background-color: #1e3a8a; color: white; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #60a5fa; }
        td { padding: 12px; border-bottom: 1px solid #27272a; }
        tr:hover { background-color: #27272a; }
        tr.hidden { display: none; }
        .status-pass { color: #4ade80; font-weight: bold; }
        .status-fail { color: #f87171; font-weight: bold; }
        .status-manual { color: #fbbf24; font-weight: bold; }
        .status-error { color: #f87171; font-weight: bold; }
        .details { font-size: 0.9em; color: #a1a1aa; }
        .remediation { font-size: 0.85em; color: #60a5fa; font-style: italic; margin-top: 5px; }

        .footer {
            margin-top: 40px;
            padding: 20px;
            text-align: center;
            background: #18181b;
            border-radius: 8px;
            color: #71717a;
            border: 1px solid #27272a;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-left">
                <h1>🔒 CIS Microsoft 365 Compliance Report</h1>
                <div class="tenant-info" onclick="toggleHeaderDetails()">
                    <span class="subtitle">TEST REPORT - Microsoft 365 Tenant</span>
                    <span class="expand-icon" id="expandIcon">▼</span>
                </div>
                <div class="header-details" id="headerDetails">
                    <div style="font-size: 0.75em; margin-top: 4px; opacity: 0.8;">CIS Benchmark v5.0.0</div>
                    <div style="font-size: 0.75em; margin-top: 4px; opacity: 0.8;">Generated: $reportDate</div>
                    <div style="font-size: 0.75em; margin-top: 4px; opacity: 0.8;">Run by: $currentUser</div>
                    <div style="font-size: 0.75em; margin-top: 4px; opacity: 0.8;">Total Controls: $totalControls (Test Data)</div>
                    <div style="font-size: 0.75em; margin-top: 4px; opacity: 0.8;">Compliance Rate: $passRate%</div>
                </div>
            </div>
            <div class="header-right">
                <div style="font-size: 1.2em; font-weight: 600;">$passRate%</div>
                <div style="opacity: 0.8;">Compliant</div>
            </div>
        </div>

        <!-- Content -->
        <div class="content">

    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="progress-bar">
            <div class="progress-fill" style="width: $passRate%">$passRate% Compliant</div>
        </div>
        <br/>
        <div class="summary-box pass" data-filter="pass" onclick="filterResults(this)">
            <strong>Passed:</strong> $passedControls
        </div>
        <div class="summary-box fail" data-filter="fail" onclick="filterResults(this)">
            <strong>Failed:</strong> $failedControls
        </div>
        <div class="summary-box manual" data-filter="manual" onclick="filterResults(this)">
            <strong>Manual:</strong> $manualControls
        </div>
        <div class="summary-box error" data-filter="error" onclick="filterResults(this)">
            <strong>Errors:</strong> $errorControls
        </div>
        <div class="summary-box" data-filter="all" onclick="filterResults(this)">
            <strong>Total Controls:</strong> $totalControls
        </div>
        <div class="summary-box level-l1" data-filter="L1" onclick="filterResults(this)">
            <strong>L1 Checks:</strong> $l1Passed / $l1Total ($l1PassRate%)
        </div>
        <div class="summary-box level-l2" data-filter="L2" onclick="filterResults(this)">
            <strong>L2 Checks:</strong> $l2Passed / $l2Total ($l2PassRate%)
        </div>
    </div>

    <!-- Search Box -->
    <div class="search-container">
        <input type="text" id="searchBox" placeholder="Search by control number, title, level (L1/L2), or status (Pass/Fail/Manual)..." onkeyup="searchTable()">
        <span class="search-icon">🔍</span>
        <span id="searchResults" class="search-results"></span>
    </div>

    <h2>Detailed Results</h2>

    <table id="resultsTable">
        <thead>
            <tr>
                <th>Control</th>
                <th>Title</th>
                <th>Level</th>
                <th>Result</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
"@

foreach ($result in $testResults | Sort-Object ControlNumber) {
    $statusClass = "status-" + $result.Result.ToLower()
    $resultLower = $result.Result.ToLower()
    $levelValue = $result.ProfileLevel
    $html += @"
            <tr data-result="$resultLower" data-level="$levelValue">
                <td><strong>$($result.ControlNumber)</strong></td>
                <td>$($result.ControlTitle)</td>
                <td>$($result.ProfileLevel)</td>
                <td class="$statusClass">$($result.Result)</td>
                <td>
                    <div class="details">$($result.Details)</div>
"@
    if ($result.Remediation -and $result.Result -eq "Fail") {
        $html += "                    <div class='remediation'>Remediation: $($result.Remediation)</div>`n"
    }
    $html += "                </td>`n            </tr>`n"
}

$html += @"
        </tbody>
    </table>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p><strong>CIS Microsoft 365 Foundations Benchmark v5.0.0</strong> | TEST REPORT with Sample Data | Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p style="margin-top: 10px; color: #fbbf24;">⚠️ This is a test report with sample data to demonstrate new features (Search Box & L1/L2 Cards)</p>
        </div>
    </div>

    <script>
        let activeFilter = null;

        function toggleHeaderDetails() {
            const details = document.getElementById('headerDetails');
            const icon = document.getElementById('expandIcon');
            details.classList.toggle('expanded');
            icon.classList.toggle('expanded');
        }

        function filterResults(box) {
            const filterValue = box.getAttribute('data-filter');
            const allRows = document.querySelectorAll('tbody tr');
            const allBoxes = document.querySelectorAll('.summary-box');

            // Clear search box when using filter buttons
            document.getElementById('searchBox').value = '';
            document.getElementById('searchResults').textContent = '';

            // Toggle filter - if same box clicked, clear filter
            if (activeFilter === filterValue) {
                // Clear filter - show all
                allRows.forEach(row => row.classList.remove('hidden'));
                allBoxes.forEach(b => b.classList.remove('active'));
                activeFilter = null;
            } else {
                // Apply new filter
                activeFilter = filterValue;
                allBoxes.forEach(b => b.classList.remove('active'));
                box.classList.add('active');

                if (filterValue === 'all') {
                    // Show all rows
                    allRows.forEach(row => row.classList.remove('hidden'));
                } else {
                    // Filter by result type or level
                    allRows.forEach(row => {
                        const rowResult = row.getAttribute('data-result');
                        const rowLevel = row.getAttribute('data-level');
                        if (rowResult === filterValue || rowLevel === filterValue) {
                            row.classList.remove('hidden');
                        } else {
                            row.classList.add('hidden');
                        }
                    });
                }
            }
        }

        function searchTable() {
            // Clear any active filter when searching
            const allBoxes = document.querySelectorAll('.summary-box');
            allBoxes.forEach(b => b.classList.remove('active'));
            activeFilter = null;

            const searchInput = document.getElementById('searchBox');
            const filter = searchInput.value.toLowerCase().trim();
            const table = document.getElementById('resultsTable');
            const tbody = table.getElementsByTagName('tbody')[0];
            const rows = tbody.getElementsByTagName('tr');
            let visibleCount = 0;
            let totalCount = rows.length;

            // If search is empty, show all rows
            if (filter === '') {
                for (let i = 0; i < rows.length; i++) {
                    rows[i].classList.remove('hidden');
                }
                document.getElementById('searchResults').textContent = '';
                return;
            }

            // Search through all rows
            for (let i = 0; i < rows.length; i++) {
                const row = rows[i];
                const cells = row.getElementsByTagName('td');

                if (cells.length > 0) {
                    const controlNumber = cells[0].textContent.toLowerCase();
                    const title = cells[1].textContent.toLowerCase();
                    const level = cells[2].textContent.toLowerCase();
                    const result = cells[3].textContent.toLowerCase();
                    const details = cells[4].textContent.toLowerCase();

                    // Check if any cell contains the search term
                    if (controlNumber.includes(filter) ||
                        title.includes(filter) ||
                        level.includes(filter) ||
                        result.includes(filter) ||
                        details.includes(filter)) {
                        row.classList.remove('hidden');
                        visibleCount++;
                    } else {
                        row.classList.add('hidden');
                    }
                }
            }

            // Update search results counter
            const resultsText = visibleCount === 1
                ? 'Found 1 result out of ' + totalCount + ' controls'
                : 'Found ' + visibleCount + ' results out of ' + totalCount + ' controls';
            document.getElementById('searchResults').textContent = resultsText;
        }
    </script>
</body>
</html>
"@

$html | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "`n✅ Test report generated successfully!" -ForegroundColor Green
Write-Host "📄 Report saved to: $reportPath" -ForegroundColor Cyan
Write-Host "`nOpening report in default browser..." -ForegroundColor Yellow

# Open the report in default browser
Start-Process $reportPath

Write-Host "`n🔍 Features to test:" -ForegroundColor Cyan
Write-Host "  1. Search Box - Type 'MFA', '5.2', 'L1', 'fail', etc." -ForegroundColor White
Write-Host "  2. L1 Checks Card - Click to filter L1 controls only" -ForegroundColor White
Write-Host "  3. L2 Checks Card - Click to filter L2 controls only" -ForegroundColor White
Write-Host "  4. Other Filter Cards - Pass, Fail, Manual, etc." -ForegroundColor White
Write-Host "  5. All features work together seamlessly!" -ForegroundColor White
Write-Host ""
