const API_URL = "http://127.0.0.1:5000";


const emailText =
    document.getElementById("emailText");

const characterCount =
    document.getElementById("characterCount");

const analyzeButton =
    document.getElementById("analyzeButton");

const loading =
    document.getElementById("loading");

const result =
    document.getElementById("result");


emailText.addEventListener(
    "input",
    function () {

        characterCount.textContent =
            `${emailText.value.length} characters`;

    }
);


async function analyzeEmail() {

    const text =
        emailText.value.trim();


    if (!text) {

        alert(
            "Please enter an email before analysis."
        );

        return;

    }


    analyzeButton.disabled = true;

    loading.classList.remove(
        "hidden"
    );

    result.classList.add(
        "hidden"
    );


    try {

        const response =
            await fetch(
                `${API_URL}/api/analyze`,
                {

                    method:
                        "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            text: text
                        })

                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Analysis failed."
            );

        }


        displayResult(data);


    } catch (error) {

        alert(
            "Analysis error: " +
            error.message
        );

        console.error(error);

    } finally {

        analyzeButton.disabled =
            false;

        loading.classList.add(
            "hidden"
        );

    }

}


function displayResult(data) {

    result.classList.remove(
        "hidden"
    );


    document.getElementById(
        "prediction"
    ).textContent =
        data.label;


    document.getElementById(
        "confidence"
    ).textContent =
        `${Number(data.confidence).toFixed(2)}%`;


    const riskScore =
        Number(data.risk_score || 0);


    document.getElementById(
        "riskScore"
    ).textContent =
        `${riskScore} / 7`;


    document.getElementById(
        "riskProgress"
    ).style.width =
        `${(riskScore / 7) * 100}%`;


    displayIndicators(
        data.indicators || []
    );


    displayURLs(
        data.url_analysis || {}
    );


    result.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

}


function displayIndicators(
    indicators
) {

    const container =
        document.getElementById(
            "indicators"
        );


    if (!indicators.length) {

        container.innerHTML =
            "<p>No major threat indicators detected.</p>";

        return;

    }


    container.innerHTML =
        indicators.map(
            item => `

                <div class="indicator">

                    <strong>
                        ${escapeHtml(item.name)}
                    </strong>

                    <p>
                        ${escapeHtml(item.description)}
                    </p>

                </div>

            `
        ).join("");

}


function displayURLs(
    analysis
) {

    const container =
        document.getElementById(
            "urlAnalysis"
        );


    const urls =
        analysis.urls || [];


    if (!urls.length) {

        container.innerHTML =
            "<p>No URLs detected in this email.</p>";

        return;

    }


    container.innerHTML =
        urls.map(
            item => `

                <div class="url-item">

                    <strong>
                        ${escapeHtml(item.risk)}
                    </strong>

                    <br>

                    <span>
                        ${escapeHtml(item.url)}
                    </span>

                    <br>

                    <small>
                        Risk score:
                        ${item.score}
                    </small>

                </div>

            `
        ).join("");

}


function escapeHtml(
    value
) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

}