<?php
/**
 * Класс для работы с криптовалютными платежами
 */
class CryptoPayment {
    
    /**
     * Получение курса криптовалюты через CoinGecko API
     */
    public function getExchangeRate($crypto, $fiat) {
        $crypto_id = strtolower($crypto == 'BTC' ? 'bitcoin' : 'litecoin');
        $fiat_lower = strtolower($fiat);
        
        // CoinGecko API (бесплатный)
        $url = "https://api.coingecko.com/api/v3/simple/price?ids={$crypto_id}&vs_currencies={$fiat_lower}";
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        
        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            error_log("CoinGecko API Error: " . $error);
            return null;
        }
        
        $data = json_decode($response, true);
        
        if (isset($data[$crypto_id][$fiat_lower])) {
            return $data[$crypto_id][$fiat_lower];
        }
        
        return null;
    }
    
    /**
     * Генерация QR-кода через Google Charts API
     */
    public function generateQRCode($crypto, $address, $amount) {
        // URI для оплаты
        $uri = strtolower($crypto) . ":" . $address . "?amount=" . $amount;
        
        // Google Charts API
        $qr_url = "https://chart.googleapis.com/chart?chs=300x300&cht=qr&chl=" . urlencode($uri);
        
        return $qr_url;
    }
    
    /**
     * Проверка транзакции через BlockCypher API
     */
    public function checkTransaction($address, $expected_amount, $crypto, $tx_hash = null) {
        $token = BLOCKCYPHER_TOKEN;
        $network = strtolower($crypto);
        $chain = "main";  // Основная сеть
        
        // Если есть хеш транзакции, проверяем её
        if ($tx_hash) {
            $url = "https://api.blockcypher.com/v1/{$network}/{$chain}/txs/{$tx_hash}?token={$token}";
            
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            
            $response = curl_exec($ch);
            $error = curl_error($ch);
            curl_close($ch);
            
            if ($error) {
                error_log("BlockCypher API Error: " . $error);
                return false;
            }
            
            $data = json_decode($response, true);
            
            // Проверяем, что транзакция подтверждена и получена ожидаемая сумма
            if (isset($data['confirmations']) && $data['confirmations'] > 0) {
                foreach ($data['outputs'] as $output) {
                    if (isset($output['addresses']) && in_array($address, $output['addresses'])) {
                        $received_amount = $output['value'] / 100000000;  // Конвертация из satoshi
                        
                        // Сравниваем с небольшим допуском из-за возможных комиссий
                        if (abs($received_amount - $expected_amount) < 0.00001) {
                            return true;
                        }
                    }
                }
            }
            
            return false;
        }
        
        // Если нет хеша, проверяем адрес на наличие неподтвержденных транзакций
        $url = "https://api.blockcypher.com/v1/{$network}/{$chain}/addrs/{$address}?token={$token}&unspentOnly=true";
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        
        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            error_log("BlockCypher API Error: " . $error);
            return false;
        }
        
        $data = json_decode($response, true);
        
        if (!isset($data['txrefs']) && !isset($data['unconfirmed_txrefs'])) {
            return false;
        }
        
        // Проверяем подтвержденные транзакции
        if (isset($data['txrefs'])) {
            foreach ($data['txrefs'] as $tx) {
                $amount = $tx['value'] / 100000000;  // Конвертация из satoshi
                
                if (abs($amount - $expected_amount) < 0.00001) {
                    return [
                        'confirmed' => true,
                        'tx_hash' => $tx['tx_hash'],
                        'confirmations' => $tx['confirmations']
                    ];
                }
            }
        }
        
        // Проверяем неподтвержденные транзакции
        if (isset($data['unconfirmed_txrefs'])) {
            foreach ($data['unconfirmed_txrefs'] as $tx) {
                $amount = $tx['value'] / 100000000;  // Конвертация из satoshi
                
                if (abs($amount - $expected_amount) < 0.00001) {
                    return [
                        'confirmed' => false,
                        'tx_hash' => $tx['tx_hash'],
                        'confirmations' => 0
                    ];
                }
            }
        }
        
        return false;
    }
}
