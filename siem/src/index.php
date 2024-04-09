<?php

$log = array_reverse(file("/var/log/fromapache"));


$numTotalLogs = count($log);
$numTotalAlerts = 0;

$allLogs = [];
$alertLogs = [];

foreach ($log as $line) {

    $row = explode(" ", $line, 7);

    $buffer = ["datetime" => implode(" ", [$row[0], $row[1], $row[2], $row[3]]), "service" => $row[4], "source" => $row[5], "message" => $row[6]];

    if (str_starts_with($row[5], "cse498_hids")) {

        $alertLogs[] = $buffer;
        $numTotalAlerts++;
    }

    $allLogs[] = $buffer;
}

function printRow($row) {

    echo "<tr>";
    echo "<td>" . $row["datetime"] . "</td>";
    echo "<td>" . $row["service"] . "</td>";
    echo "<td>" . $row["source"] . "</td>";
    echo "<td>" . $row["message"] . "</td>";
    echo "</tr>";
}

?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIEM</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
</head>
<body>

    <div class="container">
        <div class="row my-5">
            <div class="col-7">
                <h2 class="bg-primary h3 text-light p-2 border rounded">Alerts</h2>
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Data/Time</th>
                            <th>Service</th>
                            <th>Source</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                            foreach ($alertLogs as $alert) { printRow($alert); }
                        ?>
                    </tbody>
                </table>
            </div>
            <div class="col-5">
                <canvas id="myChart" style="width:100%;max-width:700px"></canvas>
            </div>
        </div>

        <h2 class="bg-primary h3 text-light p-2 border rounded">All logs</h2>

        <table class="table table-striped">
            <thead class="thead-dark bg-dark">
                <tr class="thead-dark bg-dark">
                    <th scope="col">Date/TIme</th>
                    <th scope="col">Service</th>
                    <th scope="col">Source</th>
                    <th scope="col">Message</th>
                </tr>
            </thead>
            <tbody>
                <?php
                    foreach ($allLogs as $row) { printRow($row); }
                ?>
            </tbody>
        </table>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.9.4/Chart.js"></script>

    <script>

        var xValues = ["Info", "Alerts"];
        var yValues = [<?php echo $numTotalLogs; ?>, <?php echo $numTotalAlerts; ?>];
        var barColors = ["green", "blue"];

        const chart = new Chart("myChart", {
            type: "pie",
            data: {
                labels: xValues,
                datasets: [{
                backgroundColor: barColors,
                data: yValues
                }]
            },
            options: {
                title: {
                display: true,
                text: "Severities"
                }
            }
        });
    </script>
</body>
</html>
