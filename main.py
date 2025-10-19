<?php
/**
Класс для работы с Telegram API:
<?php
/**
 * Класс для работы с Telegram Bot API
 */
class TelegramAPI {
    private $token;
    private $api_url;
    
    public function __construct($token) {
        $this->token = $token;
        $this->api_url = "https://api.telegram.org/bot{$token}/";
    }
    
    /**
     * Отправка сообщения
     */
    public function sendMessage($chat_id, $text, $keyboard = null, $parse_mode = null) {
        $data = [
            'chat_id' => $chat_id,
            'text' => $text
        ];
        
        if ($keyboard) {
            $data['reply_markup'] = json_encode($keyboard);
        }
        
        if ($parse_mode) {
            $data['parse_mode'] = $parse_mode;
        }
        
        return $this->request('sendMessage', $data);
    }
    
    /**
     * Отправка фото
     */
    public function sendPhoto($chat_id, $photo, $caption = null, $keyboard = null) {
        $data = [
            'chat_id' => $chat_id,
            'photo' => $photo
        ];
        
        if ($caption) {
            $data['caption'] = $caption;
        }
        
        if ($keyboard) {
            $data['reply_markup'] = json_encode($keyboard);
        }
        
        return $this->request('sendPhoto', $data);
    }
    
    /**
     * Ответ на callback query
     */
    public function answerCallbackQuery($callback_id, $text = null, $show_alert = false) {
        $data = ['callback_query_id' => $callback_id];
        
        if ($text) {
            $data['text'] = $text;
        }
        
        if ($show_alert) {
            $data['show_alert'] = true;
        }
        
        return $this->request('answerCallbackQuery', $data);
    }
    
    /**
     * Редактирование сообщения
     */
    public function editMessageText($chat_id, $message_id, $text, $keyboard = null, $parse_mode = null) {
        $data = [
            'chat_id' => $chat_id,
            'message_id' => $message_id,
            'text' => $text
        ];
        
        if ($keyboard) {
            $data['reply_markup'] = json_encode($keyboard);
        }
        
        if ($parse_mode) {
            $data['parse_mode'] = $parse_mode;
        }
        
        return $this->request('editMessageText', $data);
    }
    
    /**
     * Удаление сообщения
     */
    public function deleteMessage($chat_id, $message_id) {
        $data = [
            'chat_id' => $chat_id,
            'message_id' => $message_id
        ];
        
        return $this->request('deleteMessage', $data);
    }
    
    /**
     * Установка webhook
     */
    public function setWebhook($url) {
        return $this->request('setWebhook', ['url' => $url]);
    }
    
    /**
     * Получение информации о webhook
     */
    public function getWebhookInfo() {
        return $this->request('getWebhookInfo');
    }
    
    /**
     * Выполнение запроса к API
     */
    private function request($method, $data = []) {
        $url = $this->api_url . $method;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        
        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            error_log("Telegram API Error: " . $error);
            return false;
        }
        
        $result = json_decode($response, true);
        
        // Логируем ошибки API
        if (!isset($result['ok']) || $result['ok'] !== true) {
            error_log("Telegram API Error: " . json_encode($result));
        }
        
        return $result;
    }
}
 