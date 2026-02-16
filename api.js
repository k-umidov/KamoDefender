// ============================================
// API Integration Module for KamoDefender
// ============================================

// API Configuration
const API_CONFIG = {
    // Have I Been Pwned API для проверки скомпрометированных паролей
    hibp: {
        baseUrl: 'https://api.pwnedpasswords.com/range/',
        enabled: true
    },
    // VirusTotal API для проверки URL (требует API ключ)
    virustotal: {
        baseUrl: 'https://www.virustotal.com/api/v3/',
        enabled: false, // Установите true и добавьте ключ для активации
        apiKey: '' // Добавьте ваш API ключ здесь
    }
};

// ============================================
// Have I Been Pwned - Проверка паролей
// ============================================

/**
 * Проверяет пароль в базе данных утечек Have I Been Pwned
 * Использует k-Anonymity модель - отправляет только первые 5 символов SHA-1 хеша
 */
async function checkPasswordBreach(password) {
    if (!API_CONFIG.hibp.enabled) {
        return {
            breached: false,
            count: 0,
            message: 'Проверка утечек отключена'
        };
    }

    try {
        // Создаем SHA-1 хеш пароля
        const hash = await sha1Hash(password);
        const prefix = hash.substring(0, 5).toUpperCase();
        const suffix = hash.substring(5).toUpperCase();

        // Запрос к API
        const response = await fetch(API_CONFIG.hibp.baseUrl + prefix, {
            method: 'GET',
            headers: {
                'Add-Padding': 'true' // Дополнительная приватность
            }
        });

        if (!response.ok) {
            throw new Error('API недоступен');
        }

        const data = await response.text();
        const hashes = data.split('\n');

        // Ищем совпадение
        for (const line of hashes) {
            const [hashSuffix, count] = line.split(':');
            if (hashSuffix === suffix) {
                return {
                    breached: true,
                    count: parseInt(count),
                    message: `⚠️ ВНИМАНИЕ! Этот пароль найден в ${parseInt(count).toLocaleString('ru-RU')} утечках данных!`
                };
            }
        }

        return {
            breached: false,
            count: 0,
            message: '✅ Пароль не найден в известных утечках'
        };

    } catch (error) {
        console.error('Ошибка проверки HIBP:', error);
        return {
            breached: false,
            count: 0,
            message: '⚠️ Не удалось проверить базу утечек',
            error: true
        };
    }
}

/**
 * Создает SHA-1 хеш строки
 */
async function sha1Hash(str) {
    const buffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================
// VirusTotal - Проверка URL
// ============================================

/**
 * Проверяет URL через VirusTotal API
 * Требует API ключ (бесплатный лимит: 4 запроса/минуту)
 */
async function checkURLWithVirusTotal(url) {
    if (!API_CONFIG.virustotal.enabled || !API_CONFIG.virustotal.apiKey) {
        return {
            scanAvailable: false,
            message: 'VirusTotal API не настроен'
        };
    }

    try {
        // Кодируем URL для отправки
        const urlId = btoa(url).replace(/=/g, '');

        const response = await fetch(
            `${API_CONFIG.virustotal.baseUrl}urls/${urlId}`,
            {
                method: 'GET',
                headers: {
                    'x-apikey': API_CONFIG.virustotal.apiKey
                }
            }
        );

        if (!response.ok) {
            if (response.status === 404) {
                // URL не найден в базе, отправляем на сканирование
                return await submitURLToVirusTotal(url);
            }
            throw new Error('Ошибка API');
        }

        const data = await response.json();
        const stats = data.data.attributes.last_analysis_stats;

        return {
            scanAvailable: true,
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            message: stats.malicious > 0
                ? `⚠️ ${stats.malicious} антивирусов отметили этот URL как вредоносный!`
                : '✅ URL не отмечен как вредоносный'
        };

    } catch (error) {
        console.error('Ошибка VirusTotal:', error);
        return {
            scanAvailable: false,
            message: 'Не удалось проверить URL',
            error: true
        };
    }
}

/**
 * Отправляет URL на сканирование в VirusTotal
 */
async function submitURLToVirusTotal(url) {
    try {
        const formData = new FormData();
        formData.append('url', url);

        const response = await fetch(
            `${API_CONFIG.virustotal.baseUrl}urls`,
            {
                method: 'POST',
                headers: {
                    'x-apikey': API_CONFIG.virustotal.apiKey
                },
                body: formData
            }
        );

        if (!response.ok) throw new Error('Ошибка отправки');

        return {
            scanAvailable: true,
            pending: true,
            message: '🔄 URL отправлен на сканирование. Повторите проверку через минуту.'
        };

    } catch (error) {
        console.error('Ошибка отправки VirusTotal:', error);
        return {
            scanAvailable: false,
            message: 'Не удалось отправить на сканирование',
            error: true
        };
    }
}

// ============================================
// IP Geolocation API (бесплатный сервис)
// ============================================

/**
 * Получает информацию о местоположении домена
 */
async function getIPInfo(domain) {
    try {
        // Убираем протокол и путь, оставляем только домен
        const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];

        const response = await fetch(`https://ipapi.co/${cleanDomain}/json/`);

        if (!response.ok) throw new Error('API недоступен');

        const data = await response.json();

        if (data.error) {
            return {
                available: false,
                message: 'Информация недоступна'
            };
        }

        return {
            available: true,
            country: data.country_name || 'Неизвестно',
            city: data.city || 'Неизвестно',
            org: data.org || 'Неизвестно',
            message: `📍 ${data.country_name}, ${data.city} | ${data.org}`
        };

    } catch (error) {
        console.error('Ошибка IP Info:', error);
        return {
            available: false,
            message: 'Не удалось получить информацию о местоположении'
        };
    }
}

// ============================================
// Export для использования в основном скрипте
// ============================================

// Экспортируем функции для глобального использования
if (typeof window !== 'undefined') {
    window.SecurityAPI = {
        checkPasswordBreach,
        checkURLWithVirusTotal,
        getIPInfo,
        config: API_CONFIG
    };
}
