
const codeBox = document.getElementById("code");
const scanStatus = document.getElementById("scanStatus");
const aiStatus = document.getElementById("aiStatus");
const aiResult = document.getElementById("aiResult");
const findingsBox = document.getElementById("findings");
const analyzeBtn = document.getElementById("analyzeBtn");

const demoCode = `import subprocess
import pickle

def run_command(user_input):
    subprocess.run(user_input, shell=True)

def calculate(expression):
    return eval(expression)

def load_data(raw_data):
    return pickle.loads(raw_data)
`;

document.getElementById("demoBtn").addEventListener("click", () => {
    codeBox.value = demoCode;
    scanStatus.textContent = "Demo code loaded. Select Analyze code to begin.";
    aiStatus.textContent = "Waiting for code analysis.";
    aiResult.textContent = "";
});

document.getElementById("clearBtn").addEventListener("click", () => {
    codeBox.value = "";
    findingsBox.replaceChildren();
    findingsBox.appendChild(makeText(
        "div", "empty-state",
        "Ready to inspect. Your findings will appear here after analysis."
    ));

    ["total", "highCount", "otherCount"].forEach(id => {
        document.getElementById(id).textContent = "0";
    });

    scanStatus.textContent = "";
    aiStatus.textContent = "Waiting for a code analysis.";
    aiResult.textContent = "";
});

function makeText(tag, className, value) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = value || "";
    return element;
}

function renderFindings(items) {
    findingsBox.replaceChildren();

    const highCount = items.filter(item => item.severity === "High").length;
    document.getElementById("total").textContent = items.length;
    document.getElementById("highCount").textContent = highCount;
    document.getElementById("otherCount").textContent = items.length - highCount;

    if (!items.length) {
        const empty = makeText(
            "div", "empty-state",
            "No matching patterns were found. This does not prove the code is secure."
        );
        findingsBox.appendChild(empty);
        return;
    }

    items.forEach(item => {
        const card = makeText("article", "finding", "");
        const top = makeText("div", "finding-top", "");

        top.appendChild(makeText("h3", "", item.title));
        top.appendChild(makeText("span", "severity", item.severity));
        card.appendChild(top);

        card.appendChild(makeText("div", "line", `Line ${item.line}`));
        card.appendChild(makeText("p", "detail", item.detail));
        card.appendChild(makeText("p", "fix", `Suggested fix: ${item.fix}`));
        card.appendChild(makeText("div", "line", `Code: ${item.source}`));

        findingsBox.appendChild(card);
    });
}

analyzeBtn.addEventListener("click", async () => {
    const code = codeBox.value.trim();

    if (!code) {
        scanStatus.textContent = "Please paste Python code or load the demo first.";
        return;
    }

    analyzeBtn.disabled = true;
    scanStatus.textContent = "Scanning code...";
    aiStatus.textContent = "Preparing AI review...";
    aiResult.textContent = "";

    try {
        const scanResponse = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code })
        });

        const scanData = await scanResponse.json();

        if (!scanResponse.ok) {
            throw new Error(scanData.error || "Static scan failed.");
        }

        renderFindings(scanData.findings);
        scanStatus.textContent = "Static scan complete. Requesting local AI review...";
        aiStatus.textContent = "Qwen3 is generating the report. This may take a little while.";

        const aiResponse = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code,
                findings: scanData.findings
            })
        });

        const aiData = await aiResponse.json();

        if (!aiResponse.ok) {
            throw new Error(aiData.error || "AI analysis failed.");
        }

        aiResult.textContent = aiData.analysis;
        aiStatus.textContent = `AI review complete · Model: ${aiData.model}`;
        scanStatus.textContent = "Analysis complete.";
    } catch (error) {
        aiStatus.textContent = "The analysis could not be completed.";
        aiResult.textContent = error.message;
        scanStatus.textContent = "Check the message in the AI review section.";
    } finally {
        analyzeBtn.disabled = false;
    }
});
