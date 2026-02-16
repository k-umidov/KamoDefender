// Tab Switching Functionality
document.querySelectorAll('.tab-btn').forEach(button => {
    button.addEventListener('click', () => {
        // Remove active class from all buttons and tabs
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

        // Add active class to clicked button
        button.classList.add('active');

        // Show corresponding tab
        const tabId = button.dataset.tab + '-tab';
        document.getElementById(tabId).classList.add('active');
    });
});

// Password Visibility Toggle
function togglePasswordVisibility() {
    const passwordInput = document.getElementById('password-input');
    const toggleBtn = document.querySelector('.toggle-password');

    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleBtn.textContent = '🙈';
    } else {
        passwordInput.type = 'password';
        toggleBtn.textContent = '👁️';
    }
}

// Password Generator
function generatePassword() {
    const length = 16;
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const allChars = uppercase + lowercase + numbers + symbols;

    let password = '';

    // Ensure at least one of each type
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];

    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
    }

    // Shuffle the password
    password = password.split('').sort(() => Math.random() - 0.5).join('');

    // Display generated password
    document.getElementById('generated-password').textContent = password;
    document.getElementById('generated-password-container').style.display = 'block';

    // Also fill it in the input field
    document.getElementById('password-input').value = password;

    // Show terminal log
    const terminal = document.getElementById('password-terminal');
    terminal.classList.add('show');
    clearLog('password-terminal');

    addLogLine('password-terminal', '🎲 Генерация надежного пароля...', 0);
    addLogLine('password-terminal', 'Добавление заглавных букв...', 200);
    addLogLine('password-terminal', 'Добавление цифр...', 400);
    addLogLine('password-terminal', 'Добавление специальных символов...', 600);
    addLogLine('password-terminal', 'Перемешивание символов для случайности...', 800);
    addLogLine('password-terminal', '✅ Пароль успешно создан! Энтропия: 104+ бит', 1000);
}

// Copy Password to Clipboard
function copyPassword() {
    const password = document.getElementById('generated-password').textContent;
    const copyBtn = document.querySelector('.copy-btn');

    navigator.clipboard.writeText(password).then(() => {
        const originalText = copyBtn.textContent;
        copyBtn.textContent = '✅';
        copyBtn.style.background = 'rgba(0, 255, 159, 0.3)';
        copyBtn.style.borderColor = 'var(--cyber-green)';

        setTimeout(() => {
            copyBtn.textContent = originalText;
            copyBtn.style.background = 'rgba(0, 243, 255, 0.2)';
            copyBtn.style.borderColor = 'var(--cyber-blue)';
        }, 2000);
    }).catch(err => {
        alert('Ошибка копирования: ' + err);
    });
}


// Terminal Log Functions
function addLogLine(terminalId, message, delay = 0) {
    setTimeout(() => {
        const terminal = document.getElementById(terminalId);
        const logLine = document.createElement('div');
        logLine.className = 'log-line';
        logLine.textContent = message;
        terminal.appendChild(logLine);
        terminal.scrollTop = terminal.scrollHeight;
    }, delay);
}

function clearLog(terminalId) {
    const terminal = document.getElementById(terminalId);
    terminal.innerHTML = '';
}

// Password Security Checker
function checkPassword() {
    const password = document.getElementById('password-input').value;
    const terminal = document.getElementById('password-terminal');
    const results = document.getElementById('password-results');

    if (!password) {
        alert('Пожалуйста, введите пароль для анализа');
        return;
    }

    // Show terminal and clear previous logs
    terminal.classList.add('show');
    clearLog('password-terminal');
    results.classList.remove('show');

    // Simulate scanning process
    addLogLine('password-terminal', 'Инициализация сканера безопасности...', 0);
    addLogLine('password-terminal', 'Анализ структуры пароля...', 300);
    addLogLine('password-terminal', 'Проверка энтропии...', 600);
    addLogLine('password-terminal', 'Поиск в базах данных утечек...', 900);
    addLogLine('password-terminal', 'Оценка надежности...', 1200);

    // Calculate password strength
    setTimeout(async () => {
        const analysis = analyzePassword(password);
        displayPasswordResults(analysis);
        addLogLine('password-terminal', 'Анализ завершен успешно!', 1500);

        // Проверка через Have I Been Pwned API
        if (window.SecurityAPI && window.SecurityAPI.checkPasswordBreach) {
            addLogLine('password-terminal', 'Проверка в базе данных утечек...', 1800);

            try {
                const breachResult = await window.SecurityAPI.checkPasswordBreach(password);

                if (breachResult.breached) {
                    addLogLine('password-terminal', breachResult.message, 2100);
                    // Добавляем предупреждение в рекомендации
                    const recElement = document.getElementById('password-recommendations');
                    const currentRec = recElement.textContent;
                    recElement.innerHTML = `<span style="color: var(--cyber-red); font-weight: bold;">${breachResult.message}</span><br>${currentRec}`;
                } else if (!breachResult.error) {
                    addLogLine('password-terminal', breachResult.message, 2100);
                }
            } catch (error) {
                console.error('Ошибка проверки утечек:', error);
                addLogLine('password-terminal', '⚠️ Не удалось проверить базу утечек', 2100);
            }
        }

        setTimeout(() => {
            results.classList.add('show');
        }, 1700);
    }, 1500);
}

function analyzePassword(password) {
    let score = 0;
    let recommendations = [];

    // Length check
    if (password.length >= 12) score += 25;
    else if (password.length >= 8) score += 15;
    else recommendations.push('Используйте минимум 12 символов');

    // Uppercase check
    if (/[A-Z]/.test(password)) score += 20;
    else recommendations.push('Добавьте заглавные буквы');

    // Lowercase check
    if (/[a-z]/.test(password)) score += 20;
    else recommendations.push('Добавьте строчные буквы');

    // Numbers check
    if (/[0-9]/.test(password)) score += 20;
    else recommendations.push('Добавьте цифры');

    // Special characters check
    if (/[^A-Za-z0-9]/.test(password)) score += 15;
    else recommendations.push('Добавьте специальные символы (!@#$%^&*)');

    // Calculate entropy
    const charset =
        (/[a-z]/.test(password) ? 26 : 0) +
        (/[A-Z]/.test(password) ? 26 : 0) +
        (/[0-9]/.test(password) ? 10 : 0) +
        (/[^A-Za-z0-9]/.test(password) ? 32 : 0);

    const entropy = password.length * Math.log2(charset);

    // Determine status
    let status, statusClass;
    if (score >= 90) {
        status = '✅ ОТЛИЧНО - Пароль очень надежный';
        statusClass = 'status-safe';
    } else if (score >= 70) {
        status = '✔️ ХОРОШО - Пароль надежный';
        statusClass = 'status-safe';
    } else if (score >= 50) {
        status = '⚠️ СРЕДНЕ - Пароль требует улучшения';
        statusClass = 'status-warning';
    } else {
        status = '❌ СЛАБЫЙ - Пароль небезопасен';
        statusClass = 'status-danger';
    }

    return {
        score,
        status,
        statusClass,
        entropy: entropy.toFixed(2),
        recommendations: recommendations.length > 0 ? recommendations.join('; ') : 'Пароль соответствует всем требованиям безопасности'
    };
}

function displayPasswordResults(analysis) {
    document.getElementById('password-status').textContent = analysis.status;
    document.getElementById('password-status').className = 'result-value ' + analysis.statusClass;

    document.getElementById('password-score').textContent = analysis.score + ' / 100';
    document.getElementById('password-entropy').textContent = analysis.entropy + ' бит';
    document.getElementById('password-recommendations').textContent = analysis.recommendations;

    // Update strength bar
    const strengthBar = document.getElementById('strength-bar');
    strengthBar.style.width = analysis.score + '%';

    if (analysis.score >= 70) {
        strengthBar.style.background = 'linear-gradient(90deg, #00ff9f, #00f3ff)';
        strengthBar.style.boxShadow = '0 0 10px rgba(0, 255, 159, 0.8)';
    } else if (analysis.score >= 50) {
        strengthBar.style.background = 'linear-gradient(90deg, #ffea00, #ff9500)';
        strengthBar.style.boxShadow = '0 0 10px rgba(255, 234, 0, 0.8)';
    } else {
        strengthBar.style.background = 'linear-gradient(90deg, #ff3864, #ff006e)';
        strengthBar.style.boxShadow = '0 0 10px rgba(255, 56, 100, 0.8)';
    }
}

// URL Scanner
function checkURL() {
    const url = document.getElementById('url-input').value;
    const terminal = document.getElementById('url-terminal');
    const results = document.getElementById('url-results');

    if (!url) {
        alert('Пожалуйста, введите URL для проверки');
        return;
    }

    // Show terminal and clear previous logs
    terminal.classList.add('show');
    clearLog('url-terminal');
    results.classList.remove('show');

    // Simulate scanning process
    addLogLine('url-terminal', 'Инициализация URL сканера...', 0);
    addLogLine('url-terminal', 'Парсинг URL...', 300);
    addLogLine('url-terminal', 'Проверка SSL сертификата...', 600);
    addLogLine('url-terminal', 'Анализ доменного имени...', 900);
    addLogLine('url-terminal', 'Поиск в базах фишинговых сайтов...', 1200);
    addLogLine('url-terminal', 'Проверка репутации домена...', 1500);

    setTimeout(async () => {
        const analysis = analyzeURL(url);
        displayURLResults(analysis);
        addLogLine('url-terminal', 'Сканирование завершено!', 1800);

        // Проверка геолокации домена
        if (window.SecurityAPI && window.SecurityAPI.getIPInfo) {
            addLogLine('url-terminal', 'Получение информации о местоположении...', 2100);

            try {
                const ipInfo = await window.SecurityAPI.getIPInfo(url);

                if (ipInfo.available) {
                    addLogLine('url-terminal', ipInfo.message, 2400);

                    // Добавляем информацию в результаты
                    const domainElement = document.getElementById('url-domain');
                    domainElement.innerHTML = `${analysis.domain} <br><small style="color: var(--text-secondary);">${ipInfo.message}</small>`;
                }
            } catch (error) {
                console.error('Ошибка геолокации:', error);
            }
        }

        setTimeout(() => {
            results.classList.add('show');
        }, 2000);
    }, 1800);
}

function analyzeURL(url) {
    const threats = [];
    let isSafe = true;
    let domain = '';

    try {
        const urlObj = new URL(url);
        domain = urlObj.hostname;

        // Check for HTTPS
        if (urlObj.protocol !== 'https:') {
            threats.push('Небезопасный протокол (HTTP вместо HTTPS)');
            isSafe = false;
        }

        // Check for suspicious patterns
        if (domain.includes('login') || domain.includes('verify') || domain.includes('secure')) {
            threats.push('Подозрительные слова в домене');
            isSafe = false;
        }

        // Check for IP address instead of domain
        if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
            threats.push('Используется IP-адрес вместо доменного имени');
            isSafe = false;
        }

        // Check for excessive subdomains
        const subdomains = domain.split('.');
        if (subdomains.length > 3) {
            threats.push('Подозрительно много поддоменов');
            isSafe = false;
        }

        // Check for common phishing TLDs
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];
        if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
            threats.push('Подозрительная доменная зона');
            isSafe = false;
        }

        // Check for typosquatting (common sites)
        const commonSites = ['google', 'facebook', 'paypal', 'amazon', 'microsoft', 'apple'];
        const domainLower = domain.toLowerCase();
        for (const site of commonSites) {
            if (domainLower.includes(site) && !domainLower.includes(site + '.com')) {
                threats.push(`Возможная подделка ${site}`);
                isSafe = false;
            }
        }

    } catch (e) {
        threats.push('Неверный формат URL');
        isSafe = false;
        domain = 'Невозможно определить';
    }

    let status, statusClass, recommendation;

    if (isSafe) {
        status = '✅ БЕЗОПАСНО - URL не содержит известных угроз';
        statusClass = 'status-safe';
        recommendation = 'Сайт выглядит легитимно, но всегда проверяйте содержимое перед вводом личных данных';
    } else {
        status = '⚠️ ПОДОЗРИТЕЛЬНО - Обнаружены признаки фишинга';
        statusClass = 'status-danger';
        recommendation = 'НЕ ПЕРЕХОДИТЕ по этой ссылке и не вводите личные данные!';
    }

    return {
        status,
        statusClass,
        domain,
        threats: threats.length > 0 ? threats.join(', ') : 'Не обнаружено',
        recommendation
    };
}

function displayURLResults(analysis) {
    document.getElementById('url-status').textContent = analysis.status;
    document.getElementById('url-status').className = 'result-value ' + analysis.statusClass;
    document.getElementById('url-domain').textContent = analysis.domain;
    document.getElementById('url-threats').textContent = analysis.threats;
    document.getElementById('url-threats').className = analysis.threats === 'Не обнаружено' ? 'result-value status-safe' : 'result-value status-danger';
    document.getElementById('url-recommendation').textContent = analysis.recommendation;
}

// File Scanner
let selectedFile = null;

// Drag and drop functionality
const uploadZone = document.getElementById('upload-zone');

uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('dragover');
});

uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('dragover');
});

uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');

    const files = e.dataTransfer.files;
    if (files.length > 0) {
        selectedFile = files[0];
        updateUploadZone();
    }
});

function handleFileSelect(event) {
    selectedFile = event.target.files[0];
    updateUploadZone();
}

function updateUploadZone() {
    if (selectedFile) {
        uploadZone.innerHTML = `
            <div class="upload-icon">✅</div>
            <div class="upload-text">
                Файл выбран: <strong>${selectedFile.name}</strong>
            </div>
        `;
        document.getElementById('scan-file-btn').style.display = 'inline-block';
    }
}

function scanFile() {
    if (!selectedFile) {
        alert('Пожалуйста, выберите файл для сканирования');
        return;
    }

    const terminal = document.getElementById('file-terminal');
    const results = document.getElementById('file-results');

    // Show terminal and clear previous logs
    terminal.classList.add('show');
    clearLog('file-terminal');
    results.classList.remove('show');

    // Simulate scanning process
    addLogLine('file-terminal', 'Инициализация файлового сканера...', 0);
    addLogLine('file-terminal', 'Загрузка файла в изолированную среду...', 300);
    addLogLine('file-terminal', 'Проверка расширения файла...', 600);
    addLogLine('file-terminal', 'Анализ сигнатур...', 900);
    addLogLine('file-terminal', 'Поиск вредоносного кода...', 1200);
    addLogLine('file-terminal', 'Проверка на троянские программы...', 1500);
    addLogLine('file-terminal', 'Проверка на шпионское ПО...', 1800);

    setTimeout(() => {
        const analysis = analyzeFile(selectedFile);
        displayFileResults(analysis);
        addLogLine('file-terminal', 'Сканирование завершено!', 2100);

        setTimeout(() => {
            results.classList.add('show');
        }, 2300);
    }, 2100);
}

function analyzeFile(file) {
    const issues = [];
    let isSafe = true;

    // Dangerous extensions
    const dangerousExtensions = [
        '.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js',
        '.jar', '.msi', '.dll', '.sys', '.drv'
    ];

    const fileName = file.name.toLowerCase();
    const fileExt = fileName.substring(fileName.lastIndexOf('.'));

    if (dangerousExtensions.includes(fileExt)) {
        issues.push('Потенциально опасное расширение файла');
        isSafe = false;
    }

    // Check file size (suspiciously small executables)
    if (dangerousExtensions.includes(fileExt) && file.size < 1024) {
        issues.push('Подозрительно малый размер исполняемого файла');
        isSafe = false;
    }

    // Check for double extensions
    if ((fileName.match(/\./g) || []).length > 1) {
        issues.push('Обнаружено двойное расширение (возможная маскировка)');
        isSafe = false;
    }

    // Check for suspicious names
    const suspiciousNames = ['crack', 'keygen', 'patch', 'hack', 'cheat', 'virus', 'trojan'];
    if (suspiciousNames.some(name => fileName.includes(name))) {
        issues.push('Подозрительное имя файла');
        isSafe = false;
    }

    let status, statusClass;

    if (isSafe) {
        status = '✅ БЕЗОПАСНО - Угрозы не обнаружены';
        statusClass = 'status-safe';
    } else {
        status = '⚠️ ОПАСНО - Обнаружены подозрительные признаки';
        statusClass = 'status-danger';
    }

    return {
        name: file.name,
        size: formatFileSize(file.size),
        type: file.type || 'Неизвестный тип',
        status,
        statusClass,
        issues: issues.length > 0 ? issues.join(', ') : 'Не обнаружено'
    };
}

function displayFileResults(analysis) {
    document.getElementById('file-name').textContent = analysis.name;
    document.getElementById('file-size').textContent = analysis.size;
    document.getElementById('file-type').textContent = analysis.type;
    document.getElementById('file-status').textContent = analysis.status;
    document.getElementById('file-status').className = 'result-value ' + analysis.statusClass;
    document.getElementById('file-issues').textContent = analysis.issues;
    document.getElementById('file-issues').className = analysis.issues === 'Не обнаружено' ? 'result-value status-safe' : 'result-value status-danger';
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}
