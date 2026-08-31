// Fix for Leaflet's default icon paths when using a CDN
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});

// Store chart instances to destroy them before re-rendering
let chartInstances = {};
let mapInstance = null;

document.addEventListener('DOMContentLoaded', function () {
    console.log('Dashboard JS loaded');
    fetchDashboardData();
    addFilterEventListeners();
});

function addFilterEventListeners() {
    const filters = ['start_date_filter', 'end_date_filter', 'ranger_filter', 'incident_type_filter', 'severity_filter'];
    filters.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener('change', () => fetchDashboardData());
        }
    });

    const resetButton = document.getElementById('reset_filters_btn');
    if (resetButton) {
        resetButton.addEventListener('click', () => {
            filters.forEach(id => {
                const element = document.getElementById(id);
                if (element.tagName === 'SELECT') {
                    element.value = '';
                } else {
                    element.value = null;
                }
            });
            fetchDashboardData();
        });
    }
}

function buildApiUrl() {
    let url = '/api/dashboard_data?';
    const params = new URLSearchParams();
    
    const startDate = document.getElementById('start_date_filter').value;
    if (startDate) params.append('start_date', startDate);

    const endDate = document.getElementById('end_date_filter').value;
    if (endDate) params.append('end_date', endDate);

    const rangerName = document.getElementById('ranger_filter').value;
    if (rangerName) params.append('ranger_name', rangerName);
    
    const incidentType = document.getElementById('incident_type_filter').value;
    if (incidentType) params.append('incident_type', incidentType);
    
    const severity = document.getElementById('severity_filter').value;
    if (severity) params.append('severity_level', severity);

    return url + params.toString();
}

async function fetchDashboardData() {
    const apiUrl = buildApiUrl();
    console.log(`Fetching data from: ${apiUrl}`);
    
    try {
        const response = await fetch(apiUrl);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Data fetched from API:', data);

        // Clear old visualizations before rendering new ones
        clearVisualizations();

        // Populate filters with new dynamic options
        populateFilterOptions(data.filter_options);

        // Render the different sections of the dashboard
        renderExecutiveSummary(data.executive_summary);
        renderTrendCharts(data.trend_analysis);
        renderRootCauseCharts(data.root_cause_analysis);
        renderMap(data.incident_locations);

    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        const dashboardContainer = document.querySelector('.dashboard__container');
        if (dashboardContainer) {
            dashboardContainer.innerHTML = '<p style="color: red;">Could not load dashboard data. Please try again later.</p>';
        }
    }
}

function populateFilterOptions(options) {
    if (!options) return;

    // Helper function to populate a single select element
    const populateSelect = (elementId, optionList) => {
        const select = document.getElementById(elementId);
        if (!select) return;
        
        const selectedValue = select.value; // Preserve current selection
        
        // Clear old options, keeping the first one ("All")
        while (select.options.length > 1) {
            select.remove(1);
        }

        // Add new options
        optionList.forEach(name => {
            const option = document.createElement('option');
            option.value = name;
            option.textContent = name;
            select.appendChild(option);
        });

        // Restore selection if possible
        if (optionList.includes(selectedValue)) {
            select.value = selectedValue;
        }
    };
    
    populateSelect('ranger_filter', options.ranger_names);
    populateSelect('incident_type_filter', options.incident_types);
    populateSelect('severity_filter', options.severity_levels);
}

function clearVisualizations() {
    // Destroy charts
    Object.keys(chartInstances).forEach(id => {
        if (chartInstances[id]) {
            chartInstances[id].destroy();
            delete chartInstances[id];
        }
    });

    // Remove map
    if (mapInstance) {
        mapInstance.remove();
        mapInstance = null;
    }
}

function renderExecutiveSummary(summaryData) {
    if (!summaryData) return;
    document.getElementById('card-total-incidents').innerHTML = `<h4 class="dashboard__card-title">Total Incidents</h4><p class="dashboard__card-value">${summaryData.total_incidents}</p>`;
    document.getElementById('card-avg-response-time').innerHTML = `<h4 class="dashboard__card-title">Avg. Response Time</h4><p class="dashboard__card-value">${summaryData.avg_response_time_minutes} <span class="dashboard__card-unit">min</span></p>`;
    document.getElementById('card-total-area').innerHTML = `<h4 class="dashboard__card-title">Total Affected Area</h4><p class="dashboard__card-value">${summaryData.total_affected_area_km2.toLocaleString()} <span class="dashboard__card-unit">km²</span></p>`;
    document.getElementById('card-false-alarms').innerHTML = `<h4 class="dashboard__card-title">False Alarm Rate</h4><p class="dashboard__card-value">${summaryData.false_alarm_rate_percent}<span class="dashboard__card-unit">%</span></p>`;
}

function renderTrendCharts(trendData) {
    if (!trendData) return;

    const monthlyIncidentsCtx = document.getElementById('monthly-incidents-chart');
    if (monthlyIncidentsCtx && trendData.monthly_incidents) {
        chartInstances['monthly-incidents-chart'] = new Chart(monthlyIncidentsCtx, {
            type: 'line',
            data: { labels: Object.keys(trendData.monthly_incidents), datasets: [{ label: 'Number of Incidents', data: Object.values(trendData.monthly_incidents), borderColor: 'rgba(75, 192, 192, 1)', backgroundColor: 'rgba(75, 192, 192, 0.2)', fill: true, tension: 0.1 }] },
            options: { responsive: true, plugins: { title: { display: true, text: 'Monthly Incident Trend' } }, scales: { y: { beginAtZero: true } } }
        });
    }

    const avgResponseTimeCtx = document.getElementById('avg-response-time-chart');
    if (avgResponseTimeCtx && trendData.monthly_avg_response) {
        chartInstances['avg-response-time-chart'] = new Chart(avgResponseTimeCtx, {
            type: 'bar',
            data: { labels: Object.keys(trendData.monthly_avg_response), datasets: [{ label: 'Average Response Time (minutes)', data: Object.values(trendData.monthly_avg_response), backgroundColor: 'rgba(255, 159, 64, 0.6)', borderColor: 'rgba(255, 159, 64, 1)', borderWidth: 1 }] },
            options: { responsive: true, plugins: { title: { display: true, text: 'Monthly Average Response Time' } }, scales: { y: { beginAtZero: true, title: { display: true, text: 'Minutes' } } } }
        });
    }
}

function renderRootCauseCharts(rootCauseData) {
    if (!rootCauseData) return;

    const causeDistributionCtx = document.getElementById('cause-distribution-chart');
    if (causeDistributionCtx && rootCauseData.cause_distribution) {
        chartInstances['cause-distribution-chart'] = new Chart(causeDistributionCtx, {
            type: 'pie',
            data: { labels: Object.keys(rootCauseData.cause_distribution), datasets: [{ label: 'Incidents by Cause', data: Object.values(rootCauseData.cause_distribution), backgroundColor: ['rgba(255, 99, 132, 0.7)', 'rgba(54, 162, 235, 0.7)', 'rgba(255, 206, 86, 0.7)', 'rgba(75, 192, 192, 0.7)', 'rgba(153, 102, 255, 0.7)', 'rgba(255, 159, 64, 0.7)'] }] },
            options: { responsive: true, plugins: { title: { display: true, text: 'Incident Distribution by Cause' } } }
        });
    }

    const vegetationIncidentsCtx = document.getElementById('vegetation-incidents-chart');
    if (vegetationIncidentsCtx && rootCauseData.vegetation_incidents) {
        chartInstances['vegetation-incidents-chart'] = new Chart(vegetationIncidentsCtx, {
            type: 'bar',
            data: { labels: Object.keys(rootCauseData.vegetation_incidents), datasets: [{ label: 'Number of Incidents', data: Object.values(rootCauseData.vegetation_incidents), backgroundColor: 'rgba(153, 102, 255, 0.6)', borderColor: 'rgba(153, 102, 255, 1)', borderWidth: 1 }] },
            options: { indexAxis: 'y', responsive: true, plugins: { title: { display: true, text: 'Incidents by Vegetation Type' }, legend: { display: false } }, scales: { x: { beginAtZero: true } } }
        });
    }
}

function renderMap(locations) {
    if (!locations) {
        console.error('Incident locations data is missing');
        return;
    }

    // Ensure the map container is ready
    const mapContainer = document.getElementById('map');
    if (!mapContainer) return;
    mapContainer.style.height = '450px'; // Explicitly set height
    mapContainer.style.width = '100%'; // Explicitly set width

    // Initialize the map, centered on Bolivia
    mapInstance = L.map('map').setView([-16.5, -64.0], 5);

    // Add a tile layer from OpenStreetMap
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(mapInstance);

    // Create a marker cluster group
    const markers = L.markerClusterGroup();

    // Add markers to the cluster group
    locations.forEach(loc => {
        if (loc.latitude && loc.longitude) {
            const marker = L.marker([loc.latitude, loc.longitude]);
            const popupContent = `
                <b>${loc.incident_type}</b><br>
                Severity: ${loc.severity_level}<br>
                Date: ${new Date(loc.detection_time).toLocaleDateString()}
            `;
            marker.bindPopup(popupContent);
            markers.addLayer(marker);
        }
    });

    // Add the cluster group to the map
    mapInstance.addLayer(markers);

    // This is a common fix for Leaflet maps in dynamic tabs/containers.
    setTimeout(() => {
        if (mapInstance) {
            mapInstance.invalidateSize();
        }
    }, 100);
}


                

        