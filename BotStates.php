<?php
/**
 * Класс для управления состояниями диалогов Telegram бота
 */
class BotStates {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
    
    /**
     * Получение текущего состояния пользователя
     */
    public function getState($chat_id) {
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM bot_states WHERE chat_id = ?");
            $stmt->execute([$chat_id]);
            $state = $stmt->fetch();
            
            if ($state) {
                // Декодируем JSON-данные
                $state['data'] = json_decode($state['data'], true) ?: [];
            }
            
            return $state;
        } catch (PDOException $e) {
            error_log("Error getting state: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Установка состояния пользователя
     */
    public function setState($chat_id, $state_name, $data = []) {
        try {
            // Кодируем данные в JSON
            $data_json = json_encode($data);
            
            $stmt = $this->pdo->prepare("
                INSERT INTO bot_states (chat_id, state, data) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE 
                    state = VALUES(state), 
                    data = VALUES(data),
                    updated_at = CURRENT_TIMESTAMP
            ");
            
            return $stmt->execute([$chat_id, $state_name, $data_json]);
        } catch (PDOException $e) {
            error_log("Error setting state: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Обновление данных состояния
     */
    public function updateStateData($chat_id, $data = []) {
        try {
            $state = $this->getState($chat_id);
            
            if (!$state) {
                return false;
            }
            
            // Объединяем существующие данные с новыми
            $merged_data = array_merge($state['data'], $data);
            $data_json = json_encode($merged_data);
            
            $stmt = $this->pdo->prepare("
                UPDATE bot_states 
                SET data = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE chat_id = ?
            ");
            
            return $stmt->execute([$data_json, $chat_id]);
        } catch (PDOException $e) {
            error_log("Error updating state data: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Очистка состояния пользователя
     */
    public function clearState($chat_id) {
        try {
            $stmt = $this->pdo->prepare("DELETE FROM bot_states WHERE chat_id = ?");
            return $stmt->execute([$chat_id]);
        } catch (PDOException $e) {
            error_log("Error clearing state: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Проверка находится ли пользователь в определенном состоянии
     */
    public function isInState($chat_id, $state_name) {
        $state = $this->getState($chat_id);
        
        if (!$state) {
            return false;
        }
        
        return $state['state'] === $state_name;
    }
}