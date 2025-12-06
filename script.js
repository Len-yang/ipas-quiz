// 2025 資安工程師模擬測驗 - 核心邏輯 (支援單選/複選)
// v3.0 - Fixed submitQuiz reference error

// 全域變數
let currentQuestions = [];
let userAnswers = {};
let timerInterval;
let startTime;

// 初始化：更新首頁題數顯示
window.onload = function() {
    updateQuestionCounts();
};

function updateQuestionCounts() {
    try {
        if (typeof protectionQuestions !== 'undefined') {
            document.getElementById('count-prot').innerText = protectionQuestions.length;
        } else {
            document.getElementById('count-prot').innerText = "0";
        }
        
        if (typeof planningQuestions !== 'undefined') {
            document.getElementById('count-plan').innerText = planningQuestions.length;
        } else {
            document.getElementById('count-plan').innerText = "0";
        }
    } catch (e) {
        console.error("題庫載入異常:", e);
    }
}

// 載入題庫並開始
function startQuiz(type) {
    const subjectName = type === 'protection' ? '資訊安全防護實務' : '資訊安全規劃實務';
    
    // 從 questions.js 中獲取資料
    let sourceData = [];
    if (type === 'protection') {
        if (typeof protectionQuestions !== 'undefined') {
            sourceData = protectionQuestions;
        } else {
            alert('找不到防護實務題庫資料 (protectionQuestions)');
            return;
        }
    } else {
        if (typeof planningQuestions !== 'undefined') {
            sourceData = planningQuestions;
        } else {
            alert('找不到規劃實務題庫資料 (planningQuestions)');
            return;
        }
    }

    // 隨機選取 50 題 (如果題庫不足 50 題，則全選)
    currentQuestions = getRandomQuestions(sourceData, 50);
    
    // 重置狀態
    userAnswers = {};
    
    // 切換畫面
    document.getElementById('menu-screen').classList.remove('active');
    document.getElementById('result-screen').classList.remove('active'); // 確保結果頁隱藏
    document.getElementById('quiz-screen').classList.add('active');
    document.getElementById('subject-title').innerText = subjectName;
    
    renderQuestions();
    startTimer();
    updateProgressBar();
    
    // 滾動到頂部
    window.scrollTo(0, 0);
}

// Fisher-Yates Shuffle 演算法 (亂數不重複)
function getRandomQuestions(array, count) {
    // 複製陣列以免修改原始資料
    const shuffled = [...array].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, Math.min(count, array.length));
}

// 渲染題目
function renderQuestions() {
    const container = document.getElementById('question-container');
    container.innerHTML = '';

    currentQuestions.forEach((q, index) => {
        // 判斷是否為複選題 (答案長度 > 1)
        // 增加防呆：確保 q.answer 存在且為字串
        const ansStr = q.answer ? String(q.answer).trim() : "";
        const isMulti = ansStr.length > 1;
        const inputType = isMulti ? 'checkbox' : 'radio';
        // 使用 CSS class badge-multi
        const typeLabel = isMulti ? '<span class="badge-multi">複選</span>' : '';
        const hint = isMulti ? '<small style="color:#666; display:block; margin-bottom:10px;">(此題為複選題，請選擇所有正確答案)</small>' : '';

        let optionsHTML = '';
        const labels = ['A', 'B', 'C', 'D', 'E', 'F'];
        
        q.options.forEach((opt, i) => {
            const optCode = labels[i] || '?';
            optionsHTML += `
            <label class="option-label">
                <input type="${inputType}" name="q${index}" value="${optCode}" 
                    onchange="recordAnswer(${index}, '${inputType}')">
                <span>${escapeHtml(opt)}</span>
            </label>
            `;
        });

        const questionHTML = `
            <div class="question-card" id="q-${index}">
                <div style="margin-bottom: 10px;">
                    <span style="font-size: 1.2em; font-weight: bold;">第 ${index + 1} 題</span>
                    ${typeLabel}
                </div>
                <p class="question-text">${escapeHtml(q.question)}</p>
                ${hint}
                <div class="options">
                    ${optionsHTML}
                </div>
            </div>
        `;
        container.innerHTML += questionHTML;
    });
    
    // 初始化進度條數字
    const currElem = document.getElementById('current-question-num'); // 確保 index.html 有此 ID，若無可忽略
    if(currElem) currElem.innerText = "0"; 
}

// 記錄使用者答案
function recordAnswer(index, type) {
    if (type === 'radio') {
        // 單選邏輯
        const selected = document.querySelector(`input[name="q${index}"]:checked`);
        if (selected) userAnswers[index] = selected.value;
    } else {
        // 複選邏輯：收集所有被勾選的值並排序組合 (如 "A" + "C" -> "AC")
        const checked = document.querySelectorAll(`input[name="q${index}"]:checked`);
        const values = Array.from(checked).map(cb => cb.value).sort().join('');
        userAnswers[index] = values; // 存成 "AC" 這樣的字串
    }
    updateProgressBar();
}

function updateProgressBar() {
    const total = currentQuestions.length;
    // 計算已作答數量 (有值的才算)
    const answered = Object.keys(userAnswers).filter(key => userAnswers[key] && userAnswers[key].length > 0).length;
    const percentage = total === 0 ? 0 : (answered / total) * 100;
    
    const bar = document.getElementById('progress-bar');
    if (bar) bar.style.width = `${percentage}%`;
}

// 防 XSS 處理
function escapeHtml(text) {
    if (!text) return "";
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// 計時器
function startTimer() {
    if (timerInterval) clearInterval(timerInterval);
    startTime = Date.now();
    timerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const minutes = Math.floor(elapsed / 60).toString().padStart(2, '0');
        const seconds = (elapsed % 60).toString().padStart(2, '0');
        const timerElem = document.getElementById('timer');
        if (timerElem) timerElem.innerText = `${minutes}:${seconds}`;
    }, 1000);
}

// 提交試卷 (已修正 Bug)
function submitQuiz() {
    const total = currentQuestions.length;
    // 檢查已作答題數
    const answeredCount = Object.keys(userAnswers).filter(k => userAnswers[k] && userAnswers[k].length > 0).length;
    
    if (answeredCount < total) {
        if (!confirm(`您還有 ${total - answeredCount} 題未作答，確定要交卷嗎？(未作答以零分計算)`)) return;
    } else {
        if (!confirm('確定要交卷嗎？')) return;
    }
    
    clearInterval(timerInterval);
    calculateScore();
}

// 計算分數並顯示結果
function calculateScore() {
    let score = 0;
    let correctCount = 0;
    let reviewHTML = '';
    const total = currentQuestions.length;
    const scorePerQuestion = 100 / total;

    currentQuestions.forEach((q, index) => {
        // 標準化正確答案：移除空白、轉大寫
        const correct = q.answer ? q.answer.replace(/\s/g, '').toUpperCase() : "";
        // 標準化使用者答案
        const user = userAnswers[index] || '';

        // 全對才給分 (Standard Strict Scoring)
        const isCorrect = (user === correct);

        if (isCorrect) {
            score += scorePerQuestion;
            correctCount++;
        } else {
            // 錯題檢討 HTML
            // 將答案字串格式化 (如 "AC" -> "A, C")
            const userText = user ? user.split('').join(', ') : '未作答';
            const correctText = correct ? correct.split('').join(', ') : '未知';

            reviewHTML += `
                <div class="review-item">
                    <h4>第 ${index + 1} 題 <span style="color:red;font-size:0.8em;border:1px solid red;padding:2px 4px;border-radius:4px;">錯誤</span></h4>
                    <p>${escapeHtml(q.question)}</p>
                    <div style="margin-top:10px; padding-top:10px; border-top:1px dashed #eee;">
                        <p class="your-answer" style="color:#dc2626; text-decoration:line-through;">您的答案：${userText}</p>
                        <p class="correct-answer" style="color:#16a34a; font-weight:bold;">正確答案：${correctText}</p>
                        <div class="note" style="margin-top:8px; background:#f8f9fa; padding:10px; border-radius:4px; font-size:0.9em;">
                            <strong>💡 解析/出處：</strong>${escapeHtml(q.note || '暫無詳細解析')}
                        </div>
                    </div>
                </div>
            `;
        }
    });

    // 切換到結果畫面
    document.getElementById('quiz-screen').classList.remove('active');
    document.getElementById('result-screen').classList.add('active');
    
    const finalScore = Math.round(score);
    document.getElementById('final-score').innerText = finalScore;
    
    // 更新圓環顏色 (CSS Conic Gradient)
    const circle = document.querySelector('.score-circle');
    if (circle) {
        let color = '#ef4444'; // 紅
        if (finalScore >= 80) color = '#22c55e'; // 綠
        else if (finalScore >= 60) color = '#f59e0b'; // 橘
        circle.style.background = `conic-gradient(${color} ${finalScore}%, #e2e8f0 ${finalScore}%)`;
    }

    let feedback = '';
    if (finalScore >= 80) feedback = '🏆 太棒了！您的資安觀念非常紮實，通過機率很高！';
    else if (finalScore >= 70) feedback = '👍 不錯喔！觀念大致正確，再加強一下細節即可。';
    else if (finalScore >= 60) feedback = '⚠️ 低空飛過，建議針對錯題多加複習，尤其是法規部分。';
    else feedback = '💪 請再接再厲，多閱讀教材與法規，加油！';
    
    document.getElementById('feedback-text').innerText = feedback;
    
    const reviewContainer = document.getElementById('review-container');
    if (correctCount === total) {
        reviewContainer.innerHTML = '<div style="text-align:center; padding:40px; color:#22c55e;"><h3>🎉 恭喜全對！太強了！ 🎉</h3><p>您已經準備好面對考試了！</p></div>';
    } else {
        reviewContainer.innerHTML = `<h3>錯題檢討 (${total - correctCount} 題)</h3>` + reviewHTML;
    }
    
    window.scrollTo(0, 0);
}