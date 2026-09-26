/* =========================================================
   IBVAP FRONTEND APPLICATION
========================================================= */


/* =========================================================
   CONFIGURATION
========================================================= */

const API_BASE = "http://127.0.0.1:8000";

const DETECTION_REFRESH = 500;
const HEALTH_REFRESH = 3000;
const STATS_REFRESH = 5000;
const ANPR_REFRESH = 2000;
const INCIDENT_REFRESH = 3000;
const SECURITY_MAP_REFRESH = 1000;


/* =========================================================
   GLOBAL STATE
========================================================= */

let currentDetections = [];

let currentBorder = {
    defined: false,
    start_point: null,
    end_point: null
};

let currentZone = {
    defined: false,
    points: []
};

let mapDrawMode = null;
let mapDraftPoints = [];


/* =========================================================
   DOM HELPER
========================================================= */

function $(id) {
    return document.getElementById(id);
}


/* =========================================================
   API REQUEST
========================================================= */

async function apiRequest(endpoint) {

    const response = await fetch(
        `${API_BASE}${endpoint}`,
        {
            cache: "no-store"
        }
    );

    if (!response.ok) {

        throw new Error(
            `${endpoint} -> HTTP ${response.status}`
        );

    }

    return await response.json();
}


async function apiUpdate(endpoint, points) {

    const response = await fetch(
        `${API_BASE}${endpoint}`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ points })
        }
    );

    if (!response.ok) {
        throw new Error(`${endpoint} -> HTTP ${response.status}`);
    }

    return await response.json();
}


/* =========================================================
   HEALTH
========================================================= */

async function updateHealth() {

    try {

        const data =
            await apiRequest("/api/health");


        const apiRunning =
            data.api === "running";

        const aiRunning =
            data.ai_pipeline === "running";

        const cameraRunning =
            data.camera === "running";

        const databaseConnected =
            data.database === "connected";


        /* top bar */

        $("apiStatus").textContent =
            apiRunning
                ? "API RUNNING"
                : "API OFFLINE";


        $("aiStatus").textContent =
            aiRunning
                ? "AI RUNNING"
                : "AI STOPPED";


        $("cameraStatus").textContent =
            cameraRunning
                ? "CAMERA RUNNING"
                : "CAMERA OFFLINE";


        $("databaseStatus").textContent =
            databaseConnected
                ? "DATABASE"
                : "DB OFFLINE";


        /* system cards */

        $("systemApi").textContent =
            apiRunning
                ? "RUNNING"
                : "OFFLINE";


        $("systemAI").textContent =
            aiRunning
                ? "RUNNING"
                : "STOPPED";


        $("systemCamera").textContent =
            cameraRunning
                ? "RUNNING"
                : "OFFLINE";


        $("systemDatabase").textContent =
            databaseConnected
                ? "CONNECTED"
                : "DISCONNECTED";


        /* dots */

        setStatusDot(
            "apiDot",
            apiRunning
        );

        setStatusDot(
            "aiDot",
            aiRunning
        );

        setStatusDot(
            "cameraDot",
            cameraRunning
        );

        setStatusDot(
            "databaseDot",
            databaseConnected
        );

    }

    catch (error) {

        console.error(
            "Health error:",
            error
        );

        $("apiStatus").textContent =
            "API OFFLINE";

        $("systemApi").textContent =
            "OFFLINE";

        setStatusDot(
            "apiDot",
            false
        );

    }
}


/* =========================================================
   STATUS DOT
========================================================= */

function setStatusDot(id, online) {

    const element = $(id);

    if (!element) return;

    element.classList.remove(
        "green",
        "red"
    );

    element.classList.add(
        online ? "green" : "red"
    );
}


/* =========================================================
   DETECTIONS
========================================================= */

async function updateDetections() {

    try {

        const data =
            await apiRequest("/api/detections");


        currentDetections =
            Array.isArray(data.detections)
                ? data.detections
                : [];


        updateDetectionCounters(
            currentDetections
        );


        updateDetectionList(
            currentDetections
        );


        updateThreatPanel(
            currentDetections
        );


        drawDetectionBoxes(
            currentDetections
        );


        updateSecurityMapDetections(
            currentDetections
        );

    }

    catch (error) {

        console.error(
            "Detection error:",
            error
        );

    }
}


/* =========================================================
   DETECTION COUNTERS
========================================================= */

function updateDetectionCounters(
    detections
) {

    const objectCount =
        detections.length;


    const personCount =
        detections.filter(
            d =>
                String(
                    d.object_type || ""
                ).toLowerCase() === "person"
        ).length;


    const vehicleCount =
        detections.filter(
            d => {

                const type =
                    String(
                        d.object_type || ""
                    ).toLowerCase();

                return [
                    "car",
                    "truck",
                    "bus",
                    "motorcycle",
                    "vehicle"
                ].includes(type);

            }
        ).length;


    /* main statistics */

    setText(
        "liveObjectCount",
        objectCount
    );

    setText(
        "livePersonCount",
        personCount
    );

    setText(
        "liveVehicleCount",
        vehicleCount
    );


    /* camera statistics */

    setText(
        "cameraObjects",
        objectCount
    );

    setText(
        "cameraPersons",
        personCount
    );

    setText(
        "cameraVehicles",
        vehicleCount
    );


    /* map */

    setText(
        "mapObjectCount",
        `OBJECTS: ${objectCount}`
    );

    setText(
        "mapTrackedObjects",
        `TRACKED OBJECTS: ${objectCount}`
    );
}


/* =========================================================
   DETECTION LIST
========================================================= */

function updateDetectionList(
    detections
) {

    const container =
        $("detectionList");

    if (!container) return;


    if (!detections.length) {

        container.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-radar"></i>
                <span>
                    Waiting for detections...
                </span>
            </div>
        `;

        return;
    }


    container.innerHTML =
        detections
            .slice(0, 10)
            .map(
                detection => {

                    const type =
                        detection.object_type ||
                        "unknown";


                    const confidence =
                        Number(
                            detection.confidence || 0
                        );


                    const threat =
                        detection.threat_level ||
                        "LOW";


                    return `

                        <div class="detection-item">

                            <div class="object-icon">

                                <i class="fa-solid ${
                                    type === "person"
                                        ? "fa-person"
                                        : "fa-car"
                                }"></i>

                            </div>


                            <div class="item-main">

                                <strong>
                                    ${escapeHtml(
                                        type.toUpperCase()
                                    )}
                                    #${detection.track_id ?? "-"}
                                </strong>

                                <span>
                                    Confidence:
                                    ${(confidence * 100).toFixed(1)}%
                                </span>

                            </div>


                            <div class="item-value">
                                ${escapeHtml(threat)}
                            </div>

                        </div>

                    `;

                }
            )
            .join("");
}


/* =========================================================
   THREAT PANEL
========================================================= */

function updateThreatPanel(
    detections
) {

    if (!detections.length) {

        setText(
            "threatScore",
            "0"
        );

        setText(
            "threatObject",
            "—"
        );

        setText(
            "threatBehavior",
            "NORMAL"
        );

        setText(
            "threatDuration",
            "0 sec"
        );

        setText(
            "threatMovement",
            "0"
        );

        updateThreatLevel(
            "LOW"
        );

        updateThreatReasons([]);

        return;
    }


    /* highest threat */

    const selected =
        [...detections]
            .sort(
                (a, b) =>
                    Number(b.threat_score || 0) -
                    Number(a.threat_score || 0)
            )[0];


    setText(
        "threatScore",
        Math.round(
            Number(
                selected.threat_score || 0
            )
        )
    );


    setText(
        "threatObject",
        `${selected.object_type || "unknown"} #${
            selected.track_id ?? "-"
        }`
    );


    setText(
        "threatBehavior",
        selected.behavior ||
        "NORMAL"
    );


    setText(
        "threatDuration",
        `${Number(
            selected.loitering_duration || 0
        ).toFixed(1)} sec`
    );


    setText(
        "threatMovement",
        Number(
            selected.movement || 0
        ).toFixed(1)
    );


    updateThreatLevel(
        selected.threat_level || "LOW"
    );


    updateThreatReasons(
        selected.threat_reasons ||
        selected.reasons ||
        []
    );
}


/* =========================================================
   THREAT LEVEL
========================================================= */

function updateThreatLevel(
    level
) {

    const element =
        document.querySelector(
            ".threat-level"
        );


    if (!element) return;


    const normalized =
        String(level || "LOW")
            .toLowerCase();


    element.classList.remove(
        "low",
        "medium",
        "high",
        "critical"
    );


    element.classList.add(
        normalized
    );


    setText(
        "threatLevel",
        String(level || "LOW")
    );


    const circle =
        $("threatCircle");


    if (circle) {

        circle.style.setProperty(
            "--threat-level",
            normalized
        );

    }
}


/* =========================================================
   THREAT REASONS
========================================================= */

function updateThreatReasons(
    reasons
) {

    const container =
        $("threatReasons");

    if (!container) return;


    if (
        !Array.isArray(reasons) ||
        reasons.length === 0
    ) {

        container.innerHTML = `
            <div class="reason-empty">
                No active threats
            </div>
        `;

        return;
    }


    container.innerHTML =
        reasons
            .slice(0, 6)
            .map(
                reason => `

                    <div class="reason-item">

                        <i class="fa-solid fa-circle-exclamation"></i>

                        ${escapeHtml(
                            String(reason)
                        )}

                    </div>

                `
            )
            .join("");
}


/* =========================================================
   DYNAMIC BOUNDING BOXES
========================================================= */

function drawDetectionBoxes(
    detections
) {

    const canvas =
        $("detectionCanvas");

    const image =
        $("cameraFeed");


    if (!canvas || !image) return;


    const rect =
        image.getBoundingClientRect();


    const width =
        rect.width;


    const height =
        rect.height;


    if (
        width <= 0 ||
        height <= 0
    ) {
        return;
    }


    canvas.width =
        Math.round(width);

    canvas.height =
        Math.round(height);


    const ctx =
        canvas.getContext("2d");


    ctx.clearRect(
        0,
        0,
        canvas.width,
        canvas.height
    );


    const sourceWidth =
        image.naturalWidth || 640;


    const sourceHeight =
        image.naturalHeight || 480;


    const scaleX =
        width / sourceWidth;


    const scaleY =
        height / sourceHeight;


    detections.forEach(
        detection => {

            const bbox =
                detection.bbox;


            if (
                !Array.isArray(bbox) ||
                bbox.length < 4
            ) {
                return;
            }


            const [
                x1,
                y1,
                x2,
                y2
            ] = bbox;


            const x =
                x1 * scaleX;

            const y =
                y1 * scaleY;

            const w =
                (x2 - x1) * scaleX;

            const h =
                (y2 - y1) * scaleY;


            const threat =
                String(
                    detection.threat_level ||
                    "LOW"
                ).toUpperCase();


            let stroke =
                "#22c55e";


            if (
                threat === "MEDIUM"
            ) {
                stroke = "#f5c542";
            }

            else if (
                threat === "HIGH"
            ) {
                stroke = "#f97316";
            }

            else if (
                threat === "CRITICAL"
            ) {
                stroke = "#ef4444";
            }


            ctx.strokeStyle =
                stroke;

            ctx.lineWidth = 2;


            ctx.strokeRect(
                x,
                y,
                w,
                h
            );


            /* label */

            const label =
                `${detection.object_type || "object"} #${
                    detection.track_id ?? "-"
                }`;


            ctx.font =
                "11px Segoe UI";


            const textWidth =
                ctx.measureText(
                    label
                ).width;


            ctx.fillStyle =
                "rgba(0,0,0,0.75)";


            ctx.fillRect(
                x,
                Math.max(
                    0,
                    y - 19
                ),
                textWidth + 10,
                18
            );


            ctx.fillStyle =
                stroke;


            ctx.fillText(
                label,
                x + 5,
                Math.max(
                    12,
                    y - 6
                )
            );


            /* center tracking point */

            const centerX =
                (x1 + x2) /
                2 *
                scaleX;


            const centerY =
                (y1 + y2) /
                2 *
                scaleY;


            ctx.beginPath();

            ctx.arc(
                centerX,
                centerY,
                4,
                0,
                Math.PI * 2
            );

            ctx.fillStyle =
                stroke;

            ctx.fill();

        }
    );
}


/* =========================================================
   CAMERA ERROR
========================================================= */

function setupCamera() {

    const image =
        $("cameraFeed");

    const error =
        $("cameraError");


    if (!image || !error) return;


    image.addEventListener(
        "load",
        () => {

            error.style.display =
                "none";

            setText(
                "cameraResolution",
                `${image.naturalWidth || 640} × ${
                    image.naturalHeight || 480
                }`
            );

        }
    );


    image.addEventListener(
        "error",
        () => {

            error.style.display =
                "flex";

            setText(
                "cameraResolution",
                "STREAM ERROR"
            );

        }
    );

}


/* =========================================================
   SECURITY MAP
========================================================= */

async function loadSecurityBorder() {

    try {

        currentBorder =
            await apiRequest(
                "/api/border"
            );


        updateBorderStatus();

    }

    catch (error) {

        console.error(
            "Border API error:",
            error
        );

    }
}


async function loadSecurityZone() {

    try {

        currentZone =
            await apiRequest(
                "/api/zone"
            );


        updateZoneStatus();

    }

    catch (error) {

        console.error(
            "Zone API error:",
            error
        );

    }
}


function setMapDrawMode(mode) {

    mapDrawMode = mode;
    mapDraftPoints = [];

    const drawBorderButton = $("drawBorderButton");
    const drawZoneButton = $("drawZoneButton");
    const saveButton = $("saveMapButton");
    const cancelButton = $("cancelMapButton");
    const hint = $("mapDrawHint");

    drawBorderButton?.classList.toggle("active", mode === "border");
    drawZoneButton?.classList.toggle("active", mode === "zone");

    if (saveButton) saveButton.disabled = true;
    if (cancelButton) cancelButton.disabled = !mode;

    if (hint) {
        hint.textContent = mode === "border"
            ? "Click 2 points on the camera image, then select Save."
            : mode === "zone"
                ? "Click 4 points around the restricted area, then select Save."
                : "Select Draw Border or Draw Zone to configure the security map.";
    }

    updateSecurityMapDetections(currentDetections);
}


function getMapSourcePoint(event) {

    const image = $("securityMapFeed");
    if (!image) return null;

    const rect = image.getBoundingClientRect();
    const sourceWidth = image.naturalWidth || 640;
    const sourceHeight = image.naturalHeight || 360;

    if (!rect.width || !rect.height) return null;

    return [
        Math.max(0, Math.min(sourceWidth, Math.round((event.clientX - rect.left) * sourceWidth / rect.width))),
        Math.max(0, Math.min(sourceHeight, Math.round((event.clientY - rect.top) * sourceHeight / rect.height)))
    ];
}


function handleMapClick(event) {

    if (!mapDrawMode) return;

    const point = getMapSourcePoint(event);
    if (!point) return;

    const requiredPoints = mapDrawMode === "border" ? 2 : 4;
    if (mapDraftPoints.length >= requiredPoints) return;

    mapDraftPoints.push(point);

    const saveButton = $("saveMapButton");
    if (saveButton) saveButton.disabled = mapDraftPoints.length < requiredPoints;

    updateSecurityMapDetections(currentDetections);
}


async function saveMapDrawing() {

    const requiredPoints = mapDrawMode === "border" ? 2 : 4;
    if (!mapDrawMode || mapDraftPoints.length < requiredPoints) return;

    const endpoint = mapDrawMode === "border" ? "/api/border" : "/api/zone";

    try {
        await apiUpdate(endpoint, mapDraftPoints);
        await loadSecurityBorder();
        await loadSecurityZone();
        setMapDrawMode(null);
    }

    catch (error) {
        console.error("Security map update failed:", error);

        const hint = $("mapDrawHint");
        if (hint) hint.textContent = "Could not save the drawing. Check the backend connection.";
    }
}


function drawMapDraft(ctx, scaleX, scaleY) {

    if (!mapDrawMode || !mapDraftPoints.length) return;

    const color = mapDrawMode === "border" ? "#ef4444" : "#f5c542";

    ctx.save();
    ctx.strokeStyle = color;
    ctx.fillStyle = color;
    ctx.lineWidth = 2;
    ctx.setLineDash([6, 4]);
    ctx.beginPath();

    mapDraftPoints.forEach((point, index) => {
        const x = point[0] * scaleX;
        const y = point[1] * scaleY;
        if (index === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });

    if (mapDrawMode === "zone" && mapDraftPoints.length >= 3) {
        ctx.closePath();
        ctx.fillStyle = "rgba(245,197,66,0.08)";
        ctx.fill();
    }

    ctx.stroke();
    ctx.setLineDash([]);

    mapDraftPoints.forEach((point) => {
        drawMapPoint(ctx, point[0] * scaleX, point[1] * scaleY, color);
    });

    ctx.restore();
}


/* =========================================================
   BORDER STATUS
========================================================= */

function updateBorderStatus() {

    const element =
        $("borderStatus");

    if (!element) return;


    if (
        currentBorder &&
        currentBorder.defined
    ) {

        element.innerHTML = `

            <span class="status-dot green"></span>

            BORDER ACTIVE

        `;

    }

    else {

        element.innerHTML = `

            <span class="status-dot red"></span>

            BORDER NOT DEFINED

        `;

    }
}


/* =========================================================
   ZONE STATUS
========================================================= */

function updateZoneStatus() {

    const element =
        $("zoneStatus");

    if (!element) return;


    if (
        currentZone &&
        currentZone.defined
    ) {

        element.innerHTML = `

            <span class="status-dot green"></span>

            ZONE ACTIVE

        `;

    }

    else {

        element.innerHTML = `

            <span class="status-dot red"></span>

            ZONE NOT DEFINED

        `;

    }
}


/* =========================================================
   SECURITY MAP DRAW
========================================================= */

function updateSecurityMapDetections(
    detections
) {

    const canvas =
        $("securityMapCanvas");

    const image =
        $("securityMapFeed");


    if (!canvas || !image) {
        return;
    }


    const rect =
        image.getBoundingClientRect();


    const width =
        rect.width;


    const height =
        rect.height;


    if (
        width <= 0 ||
        height <= 0
    ) {
        return;
    }


    canvas.width =
        Math.round(width);

    canvas.height =
        Math.round(height);


    const ctx =
        canvas.getContext("2d");


    ctx.clearRect(
        0,
        0,
        canvas.width,
        canvas.height
    );


    const sourceWidth =
        image.naturalWidth || 640;


    const sourceHeight =
        image.naturalHeight || 480;


    const scaleX =
        width / sourceWidth;


    const scaleY =
        height / sourceHeight;


    /* ==========================================
       RESTRICTED ZONE
    ========================================== */

    if (
        currentZone &&
        currentZone.defined &&
        Array.isArray(currentZone.points) &&
        currentZone.points.length >= 3
    ) {

        ctx.beginPath();


        currentZone.points.forEach(
            (point, index) => {

                const x =
                    point[0] *
                    scaleX;

                const y =
                    point[1] *
                    scaleY;


                if (index === 0) {

                    ctx.moveTo(
                        x,
                        y
                    );

                }

                else {

                    ctx.lineTo(
                        x,
                        y
                    );

                }

            }
        );


        ctx.closePath();


        ctx.fillStyle =
            "rgba(245,197,66,0.10)";


        ctx.fill();


        ctx.strokeStyle =
            "#f5c542";


        ctx.lineWidth = 2;


        ctx.stroke();

    }


    /* ==========================================
       VIRTUAL BORDER
    ========================================== */

    if (
        currentBorder &&
        currentBorder.defined &&
        Array.isArray(
            currentBorder.start_point
        ) &&
        Array.isArray(
            currentBorder.end_point
        )
    ) {

        const start =
            currentBorder.start_point;

        const end =
            currentBorder.end_point;


        ctx.beginPath();


        ctx.moveTo(
            start[0] * scaleX,
            start[1] * scaleY
        );


        ctx.lineTo(
            end[0] * scaleX,
            end[1] * scaleY
        );


        ctx.strokeStyle =
            "#ef4444";


        ctx.lineWidth = 2;


        ctx.setLineDash(
            [10, 7]
        );


        ctx.stroke();


        ctx.setLineDash([]);


        /* border endpoints */

        drawMapPoint(
            ctx,
            start[0] * scaleX,
            start[1] * scaleY,
            "#ef4444"
        );


        drawMapPoint(
            ctx,
            end[0] * scaleX,
            end[1] * scaleY,
            "#ef4444"
        );

    }


    drawMapDraft(
        ctx,
        scaleX,
        scaleY
    );


    /* ==========================================
       TRACKED OBJECTS
    ========================================== */

    detections.forEach(
        detection => {

            const center =
                detection.center;


            if (
                !Array.isArray(center) ||
                center.length < 2
            ) {
                return;
            }


            const x =
                center[0] *
                scaleX;


            const y =
                center[1] *
                scaleY;


            let color =
                "#19c7d8";


            if (
                detection.threat_level ===
                "MEDIUM"
            ) {
                color = "#f5c542";
            }


            if (
                detection.threat_level ===
                "HIGH"
            ) {
                color = "#f97316";
            }


            if (
                detection.threat_level ===
                "CRITICAL"
            ) {
                color = "#ef4444";
            }


            drawMapPoint(
                ctx,
                x,
                y,
                color
            );


            /* track id */

            ctx.font =
                "10px Segoe UI";


            ctx.fillStyle =
                color;


            ctx.fillText(
                `#${detection.track_id ?? "-"}`,
                x + 8,
                y - 8
            );

        }
    );


    updateMapEmptyState();

}


/* =========================================================
   MAP POINT
========================================================= */

function drawMapPoint(
    ctx,
    x,
    y,
    color
) {

    ctx.beginPath();

    ctx.arc(
        x,
        y,
        5,
        0,
        Math.PI * 2
    );

    ctx.fillStyle =
        color;

    ctx.fill();


    ctx.beginPath();

    ctx.arc(
        x,
        y,
        9,
        0,
        Math.PI * 2
    );

    ctx.strokeStyle =
        color;

    ctx.globalAlpha =
        0.35;

    ctx.stroke();

    ctx.globalAlpha =
        1;
}


/* =========================================================
   MAP EMPTY STATE
========================================================= */

function updateMapEmptyState() {

    const empty =
        $("mapEmpty");

    if (!empty) return;


    const configured =
        (
            currentBorder &&
            currentBorder.defined
        ) ||
        (
            currentZone &&
            currentZone.defined
        );


    empty.style.display =
        configured
            ? "none"
            : "flex";
}


/* =========================================================
   ANPR
========================================================= */

async function updateANPR() {

    try {

        const data =
            await apiRequest(
                "/api/anpr"
            );


        const results =
            Array.isArray(data.results)
                ? data.results
                : [];


        const table =
            $("anprTable");


        if (!table) return;


        if (!results.length) {

            table.innerHTML = `

                <tr>

                    <td
                        colspan="6"
                        class="table-empty"
                    >
                        No ANPR results
                    </td>

                </tr>

            `;

            return;
        }


        table.innerHTML =
            results
                .slice(0, 20)
                .map(
                    result => `

                        <tr>

                            <td>
                                #${result.track_id ?? "-"}
                            </td>

                            <td>
                                ${escapeHtml(
                                    result.vehicle_type ||
                                    "vehicle"
                                )}
                            </td>

                            <td class="plate-number">
                                ${escapeHtml(
                                    result.plate_number ||
                                    "READING..."
                                )}
                            </td>

                            <td>
                                ${formatConfidence(
                                    result.plate_confidence
                                )}
                            </td>

                            <td>
                                ${formatConfidence(
                                    result.ocr_confidence
                                )}
                            </td>

                            <td>
                                ${formatTime(
                                    result.timestamp
                                )}
                            </td>

                        </tr>

                    `
                )
                .join("");

    }

    catch (error) {

        console.error(
            "ANPR error:",
            error
        );

    }
}


/* =========================================================
   INCIDENTS
========================================================= */

async function updateIncidents() {

    try {

        const data =
            await apiRequest(
                "/api/incidents/recent/5"
            );


        const incidents =
            Array.isArray(data.incidents)
                ? data.incidents
                : [];


        const container =
            $("incidentList");


        if (!container) return;


        if (!incidents.length) {

            container.innerHTML = `

                <div class="empty-state">

                    <i class="fa-solid fa-shield"></i>

                    <span>
                        No incidents
                    </span>

                </div>

            `;

            return;
        }


        container.innerHTML =
            incidents
                .map(
                    incident => `

                        <div class="incident-item">

                            <div class="object-icon">

                                <i class="fa-solid fa-triangle-exclamation"></i>

                            </div>


                            <div class="item-main">

                                <strong class="incident-event">

                                    ${escapeHtml(
                                        incident.event_type ||
                                        "INCIDENT"
                                    )}

                                </strong>

                                <span>

                                    Track #${
                                        incident.track_id ??
                                        "-"
                                    }

                                    •

                                    ${
                                        incident.object_type ||
                                        "unknown"
                                    }

                                </span>

                            </div>


                            <div class="incident-time">

                                ${formatTime(
                                    incident.timestamp
                                )}

                            </div>

                        </div>

                    `
                )
                .join("");

    }

    catch (error) {

        console.error(
            "Incident error:",
            error
        );

    }
}


/* =========================================================
   STATISTICS
========================================================= */

async function updateStatistics() {

    try {

        const data =
            await apiRequest(
                "/api/incidents/stats/summary"
            );


        setText(
            "totalIncidents",
            data.total_incidents ??
            data.total ??
            0
        );


        setText(
            "borderIntrusions",
            data.border_intrusions ??
            data.border_crossings ??
            0
        );


        setText(
            "zoneIntrusions",
            data.zone_intrusions ??
            0
        );


        setText(
            "loiteringEvents",
            data.loitering_events ??
            data.loitering ??
            0
        );

    }

    catch (error) {

        console.error(
            "Statistics error:",
            error
        );

    }
}


/* =========================================================
   HELPERS
========================================================= */

function setText(
    id,
    value
) {

    const element =
        $(id);

    if (element) {

        element.textContent =
            value;

    }
}


function formatConfidence(
    value
) {

    const number =
        Number(value || 0);


    if (number <= 1) {

        return `${(
            number * 100
        ).toFixed(1)}%`;

    }


    return `${number.toFixed(1)}%`;
}


function formatTime(
    value
) {

    if (!value) {
        return "—";
    }


    try {

        const date =
            new Date(value);


        if (isNaN(date.getTime())) {

            return String(value);

        }


        return date.toLocaleTimeString(
            [],
            {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            }
        );

    }

    catch {

        return String(value);

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


/* =========================================================
   IMAGE RESIZE
========================================================= */

function redrawCanvases() {

    drawDetectionBoxes(
        currentDetections
    );

    updateSecurityMapDetections(
        currentDetections
    );
}


/* =========================================================
   INITIALIZATION
========================================================= */

function initializeApplication() {

    console.log(
        "===================================="
    );

    console.log(
        "IBVAP FRONTEND INITIALIZING"
    );

    console.log(
        "API:",
        API_BASE
    );

    console.log(
        "===================================="
    );


    setupCamera();

    $("drawBorderButton")?.addEventListener(
        "click",
        () => setMapDrawMode("border")
    );

    $("drawZoneButton")?.addEventListener(
        "click",
        () => setMapDrawMode("zone")
    );

    $("saveMapButton")?.addEventListener(
        "click",
        saveMapDrawing
    );

    $("cancelMapButton")?.addEventListener(
        "click",
        () => setMapDrawMode(null)
    );

    $("securityMapFeed")?.addEventListener(
        "click",
        handleMapClick
    );


    /* initial calls */

    updateHealth();

    updateDetections();

    updateStatistics();

    updateANPR();

    updateIncidents();

    loadSecurityBorder();

    loadSecurityZone();


    /* recurring calls */

    setInterval(
        updateDetections,
        DETECTION_REFRESH
    );


    setInterval(
        updateHealth,
        HEALTH_REFRESH
    );


    setInterval(
        updateStatistics,
        STATS_REFRESH
    );


    setInterval(
        updateANPR,
        ANPR_REFRESH
    );


    setInterval(
        updateIncidents,
        INCIDENT_REFRESH
    );


    setInterval(
        async () => {

            await loadSecurityBorder();

            await loadSecurityZone();

            updateSecurityMapDetections(
                currentDetections
            );

        },
        SECURITY_MAP_REFRESH
    );


    window.addEventListener(
        "resize",
        redrawCanvases
    );


    /* smooth navigation */

    document
        .querySelectorAll(
            ".nav-item"
        )
        .forEach(
            item => {

                item.addEventListener(
                    "click",
                    () => {

                        document
                            .querySelectorAll(
                                ".nav-item"
                            )
                            .forEach(
                                nav =>
                                    nav.classList.remove(
                                        "active"
                                    )
                            );


                        item.classList.add(
                            "active"
                        );

                    }
                );

            }
        );

}


/* =========================================================
   START
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    initializeApplication
);