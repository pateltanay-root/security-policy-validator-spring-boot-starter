const projectFileInput =
    document.getElementById("projectFile");

const policyFileInput =
    document.getElementById("policyFile");

const projectName =
    document.getElementById("projectName");

const policyName =
    document.getElementById("policyName");

const analyzeButton =
    document.getElementById("analyzeButton");

const statusMessage =
    document.getElementById("statusMessage");

const violationsContainer =
    document.getElementById("violationsContainer");

const emptyState =
    document.getElementById("emptyState");

const searchInput =
    document.getElementById("searchInput");

const dropZone =
    document.getElementById("dropZone");


let currentViolations = [];

let selectedSeverity = "ALL";


projectFileInput.addEventListener(
    "change",
    () => {

        if (projectFileInput.files.length) {

            projectName.textContent =
                projectFileInput.files[0].name;
        }
    }
);


policyFileInput.addEventListener(
    "change",
    () => {

        if (policyFileInput.files.length) {

            policyName.textContent =
                policyFileInput.files[0].name;
        }
    }
);


let currentPage = 1;
const pageSize = 10;
let filteredViolations = [];


/* =================================
   DRAG AND DROP
================================= */

dropZone.addEventListener(
    "dragover",
    event => {

        event.preventDefault();

        dropZone.classList.add(
            "dragging"
        );
    }
);


dropZone.addEventListener(
    "dragleave",
    () => {

        dropZone.classList.remove(
            "dragging"
        );
    }
);


dropZone.addEventListener(
    "drop",
    event => {

        event.preventDefault();

        dropZone.classList.remove(
            "dragging"
        );


        for (const file of event.dataTransfer.files) {

            const name =
                file.name.toLowerCase();


            if (name.endsWith(".zip")) {

                const transfer =
                    new DataTransfer();

                transfer.items.add(file);

                projectFileInput.files =
                    transfer.files;

                projectName.textContent =
                    file.name;
            }


            if (
                name.endsWith(".yml")
                ||
                name.endsWith(".yaml")
            ) {

                const transfer =
                    new DataTransfer();

                transfer.items.add(file);

                policyFileInput.files =
                    transfer.files;

                policyName.textContent =
                    file.name;
            }
        }
    }
);


/* =================================
   ANALYZE
================================= */

analyzeButton.addEventListener(
    "click",
    analyzeProject
);


async function analyzeProject() {

    const project =
        projectFileInput.files[0];

    const policy =
        policyFileInput.files[0];


    if (!project) {

        showStatus(
            "Please select a Spring Boot ZIP.",
            true
        );

        return;
    }


    if (!policy) {

        showStatus(
            "Please select a policy YAML file.",
            true
        );

        return;
    }


    const formData =
        new FormData();

    formData.append(
        "project",
        project
    );

    formData.append(
        "policy",
        policy
    );


    analyzeButton.disabled = true;

    analyzeButton.textContent =
        "Analyzing...";

    showStatus(
        "Scanning project..."
    );


    try {

        const response =
            await fetch(
                "/api/analysis",
                {
                    method: "POST",
                    body: formData
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error
                ||
                "Analysis failed"
            );
        }


        displayReport(data);

        showStatus(
            "Analysis completed successfully."
        );

    } catch (error) {

        showStatus(
            error.message,
            true
        );

    } finally {

        analyzeButton.disabled = false;

        analyzeButton.textContent =
            "Analyze Project";
    }
}


/* =================================
   DISPLAY REPORT
================================= */

function displayReport(report) {

    const summary =
        report.summary || {};


    document.getElementById(
        "endpointCount"
    ).textContent =
        summary.endpoints ?? 0;


    currentViolations =
        report.violations || [];


    document.getElementById(
        "violationCount"
    ).textContent =
        currentViolations.length;


    const criticalCount =
        countSeverity(
            "CRITICAL"
        );


    const highCount =
        countSeverity(
            "HIGH"
        );


    const mediumCount =
        countSeverity(
            "MEDIUM"
        );


    document.getElementById(
        "criticalCount"
    ).textContent =
        criticalCount;


    document.getElementById(
        "highMediumCount"
    ).textContent =
        highCount + mediumCount;


    renderViolations();
}


function countSeverity(severity) {

    return currentViolations.filter(
        violation =>
            normalizeSeverity(
                violation.severity
            ) === severity
    ).length;
}


/* =================================
   RENDER VIOLATIONS
================================= */

function renderViolations() {

    violationsContainer.innerHTML = "";


    const search =
        searchInput
            .value
            .trim()
            .toLowerCase();


    filteredViolations =
        currentViolations.filter(
            violation => {

                const severity =
                    normalizeSeverity(
                        violation.severity
                    );


                const endpoint =
                    String(
                        violation.endpoint || ""
                    )
                    .toLowerCase();


                const severityMatches =
                    selectedSeverity === "ALL"
                    ||
                    severity === selectedSeverity;


                const searchMatches =
                    !search
                    ||
                    endpoint.includes(search);
					
                return (
                    severityMatches
                    &&
                    searchMatches
                );
            }
        );
		
		const start =
		    (currentPage - 1) * pageSize;

		const end =
		    start + pageSize;

		const pageItems =
		    filteredViolations.slice(
		        start,
		        end
		    );


    emptyState.style.display =
        filteredViolations.length
            ? "none"
            : "block";


    if (!filteredViolations.length) { 

        emptyState.textContent =
            currentViolations.length
                ? "No violations match the current filters."
                : "No security violations found.";

        return;
    }


	pageItems.forEach(
	    violation => {

	        violationsContainer.appendChild(
	            createViolationCard(
	                violation
	            )
	        );
	    }
	);
	
	renderPagination();
}


function createViolationCard(
    violation
) {

    const severity =
        normalizeSeverity(
            violation.severity
        );


    const card =
        document.createElement(
            "article"
        );


    card.className =
        `violation-card ${severity.toLowerCase()}`;


    const endpoint =
        escapeHtml(
            violation.endpoint
            ||
            "Unknown endpoint"
        );


    const violationType =
        escapeHtml(
            violation.violationType
            ||
            "SECURITY_VIOLATION"
        );


    const message =
        escapeHtml(
            violation.message
            ||
            "Security policy violation detected"
        );


    const expected =
        escapeHtml(
            formatValue(
                violation.expected
            )
        );


    const actual =
        escapeHtml(
            formatValue(
                violation.actual
            )
        );


    const fix =
        buildFix(
            violation
        );


    const sourceHtml =
        buildSourceLocation(
            violation.sourceLocation
        );


    card.innerHTML = `
        <div class="violation-header">

            <div class="endpoint">
                ${endpoint}
            </div>

            <span class="severity-badge">
                ${severity}
            </span>

        </div>


        <div class="violation-message">
            ${violationType}: ${message}
        </div>


        <div class="comparison">

            <div>

                <span class="comparison-title">
                    EXPECTED POLICY SECURITY
                </span>

                <span class="expected-value">
                    ${expected}
                </span>

            </div>


            <div>

                <span class="comparison-title">
                    ACTUAL IMPLEMENTED SECURITY
                </span>

                <span class="actual-value">
                    ${actual}
                </span>

            </div>

        </div>


        ${sourceHtml}


        <div class="fix-box">

            <div class="fix-header">

                <span class="fix-title">
                    💡 Recommended Solution & Code Fix
                </span>

                <button class="copy-button">
                    Copy Fix
                </button>

            </div>

            <pre class="fix-code">${escapeHtml(fix)}</pre>

        </div>
    `;


    card
        .querySelector(
            ".copy-button"
        )
        .addEventListener(
            "click",
            event =>
                copyFix(
                    fix,
                    event.target
                )
        );


    return card;
}


/* =================================
   SOURCE LOCATION
================================= */

function buildSourceLocation(
    source
) {

    if (!source) {

        return "";
    }


    const className =
        escapeHtml(
            source.className
            ||
            ""
        );


    const methodName =
        escapeHtml(
            source.methodName
            ||
            ""
        );


    const filePath =
        escapeHtml(
            source.filePath
            ||
            ""
        );


    const lineNumber =
        source.lineNumber
        &&
        source.lineNumber > 0
            ? source.lineNumber
            : "Unknown";


    return `
        <div class="source-location">

            <strong>Source:</strong>

            ${className}

            ${methodName
                ? "." + methodName + "()"
                : ""}

            ${filePath
                ? " — " + filePath
                : ""}

            ${lineNumber !== "Unknown"
                ? " — Line " + lineNumber
                : ""}

        </div>
    `;
}


/* =================================
   RECOMMENDED FIX
================================= */

function buildFix(
    violation
) {

    const endpoint =
        violation.endpoint
        ||
        "";


    let method = "GET";
    let path = endpoint;


    const colon =
        endpoint.indexOf(":");


    if (colon !== -1) {

        method =
            endpoint
                .substring(
                    0,
                    colon
                );

        path =
            endpoint
                .substring(
                    colon + 1
                );
    }


    const expected =
        formatValue(
            violation.expected
        );


    return (
`Add or update the policy definition in security-policy.yml:

policies:
  - method: ${method}
    endpoint: ${path}
    access: ROLE_BASED
    roles:
      - ${expected || "USER"}`
    );
}


/* =================================
   FILTERS
================================= */

document
    .querySelectorAll(
        ".filter"
    )
    .forEach(
        button => {

            button.addEventListener(
                "click",
                () => {

                    document
                        .querySelectorAll(
                            ".filter"
                        )
                        .forEach(
                            filter =>
                                filter.classList.remove(
                                    "active"
                                )
                        );


                    button.classList.add(
                        "active"
                    );


                    selectedSeverity =
                        button.dataset.severity;


                    renderViolations();
                }
            );
        }
    );


	searchInput.addEventListener(
	    "input",
	    () => {

	        currentPage = 1;

	        renderViolations();
	    }
	);
	
	document
	const csvBtn =
	    document.getElementById(
	        "exportCsvBtn"
	    );

	if (csvBtn) {
	    csvBtn.addEventListener(
	        "click",
	        exportCsv
	    );
	}

	function exportCsv() {

	    const rows = [
	        [
	            "Endpoint",
	            "Severity",
	            "Type",
	            "Message"
	        ]
	    ];

	    filteredViolations.forEach(
	        v => {

	            rows.push([
	                v.endpoint,
	                v.severity,
	                v.violationType,
	                v.message
	            ]);
	        }
	    );

	    const csv =
	        rows.map(
	            r => r.join(",")
	        ).join("\n");

	    const blob =
	        new Blob(
	            [csv],
	            {
	                type:
	                "text/csv"
	            }
	        );

	    const url =
	        URL.createObjectURL(
	            blob
	        );

	    const a =
	        document.createElement(
	            "a"
	        );

	    a.href = url;

	    a.download =
	        "security-report.csv";

	    a.click();
	}
	
	document
	    .getElementById(
	        "exportDocxBtn"
	    )
	    .addEventListener(
	        "click",
	        exportDocx
	    );

		async function exportDocx() {

		    const { Document, Packer, Paragraph } = window.docx;

		    const violations =
		        filteredViolations.length > 0
		            ? filteredViolations
		            : currentViolations;

		    const paragraphs = [
		        new Paragraph("Security Audit Report"),
		        new Paragraph("")
		    ];

		    violations.forEach(v => {

		        paragraphs.push(
		            new Paragraph(
		                `Severity: ${v.severity || ""}`
		            )
		        );

		        paragraphs.push(
		            new Paragraph(
		                `Endpoint: ${v.endpoint || ""}`
		            )
		        );

		        paragraphs.push(
		            new Paragraph(
		                `Type: ${v.violationType || ""}`
		            )
		        );

		        paragraphs.push(
		            new Paragraph(
		                `Message: ${v.message || ""}`
		            )
		        );

		        paragraphs.push(
		            new Paragraph("--------------------")
		        );
		    });

		    const doc = new Document({
		        sections: [{
		            children: paragraphs
		        }]
		    });

		    const blob = await Packer.toBlob(doc);

		    const link = document.createElement("a");
		    link.href = URL.createObjectURL(blob);
		    link.download = "security-report.docx";
		    link.click();
		}


/* =================================
   HELPERS
================================= */

function normalizeSeverity(
    severity
) {

    return String(
        severity || "LOW"
    )
    .toUpperCase();
}


function formatValue(
    value
) {

    if (value === null
        ||
        value === undefined
        ||
        value === "") {

        return "Not defined";
    }


    if (Array.isArray(value)) {

        return value.join(", ");
    }


    return String(value);
}


async function copyFix(
    fix,
    button
) {

    try {

        await navigator.clipboard.writeText(
            fix
        );


        const previous =
            button.textContent;


        button.textContent =
            "Copied ✓";


        setTimeout(
            () => {
                button.textContent =
                    previous;
            },
            1200
        );

    } catch {

        button.textContent =
            "Copy failed";
    }
}


function showStatus(
    message,
    error = false
) {

    statusMessage.textContent =
        message;


    statusMessage.style.color =
        error
            ? "#ff6572"
            : "#1ee889";
}

function renderPagination() {

    const pagination =
        document.getElementById(
            "pagination"
        );

    if (!pagination) return;

    pagination.innerHTML = "";

    const pages =
        Math.ceil(
            filteredViolations.length /
            pageSize
        );

    if (pages <= 1) return;

    for (
        let i = 1;
        i <= pages;
        i++
    ) {

        const btn =
            document.createElement(
                "button"
            );

        btn.textContent = i;

        btn.className =
            i === currentPage
                ? "page-btn active"
                : "page-btn";

        btn.onclick = () => {

            currentPage = i;

            renderViolations();
        };

        pagination.appendChild(btn);
    }
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