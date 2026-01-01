
document.addEventListener('DOMContentLoaded', () => {
    const menuItems = document.querySelectorAll('.menu-item');
    const viewTitle = document.getElementById('view-title');
    const contentArea = document.getElementById('content-area');
    const refreshBtn = document.getElementById('refresh-btn');
    const dllSearchHeader = document.getElementById('dll-search-header');
    const pidInput = document.getElementById('pid-input');
    const dllSearchBtn = document.getElementById('dll-search-btn');
    const handleSearchHeader = document.getElementById('handle-search-header');
    const handlePidInput = document.getElementById('handle-pid-input');
    const handleSearchBtn = document.getElementById('handle-search-btn');
    const dumpHeader = document.getElementById('dump-header');
    const dumpPidInput = document.getElementById('dump-pid-input');
    const dumpBtn = document.getElementById('dump-btn');

    const views = {
        processes: { title: 'Process Monitor', render: renderProcessView },
        network: { title: 'Network Connections', render: renderNetworkView },
        dlls: { title: 'DLL Search', render: renderDllView },
        handles: { title: 'Handle Search', render: renderHandleView },
        dump: { title: 'Process Dump', render: renderDumpView },
        autoruns: { title: 'Autoruns', render: renderComingSoon },
        yara: { title: 'YARA Scan', render: renderComingSoon },
    };

    let currentView = 'processes';

    function switchView(viewName) {
        currentView = viewName;

        // Update active menu item
        menuItems.forEach(item => {
            item.classList.toggle('active', item.dataset.view === viewName);
        });

        // Update title
        viewTitle.textContent = views[viewName].title;

        // Toggle header controls
        refreshBtn.classList.add('hidden');
        dllSearchHeader.classList.add('hidden');
        handleSearchHeader.classList.add('hidden');
        dumpHeader.classList.add('hidden');

        if (viewName === 'dlls') {
            dllSearchHeader.classList.remove('hidden');
        } else if (viewName === 'handles') {
            handleSearchHeader.classList.remove('hidden');
        } else if (viewName === 'dump') {
            dumpHeader.classList.remove('hidden');
        } else if (viewName === 'processes' || viewName === 'network') {
            refreshBtn.classList.remove('hidden');
        }

        // Render view
        views[viewName].render();
    }

    async function fetchData(url) {
        contentArea.innerHTML = '<div class="loading">Loading...</div>';
        try {
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const result = await response.json();
            if (!result.success) {
                throw new Error(result.error || 'API returned an error');
            }
            return result.data;
        } catch (error) {
            console.error('Fetch error:', error);
            contentArea.innerHTML = `<div class="error">Failed to load data: ${error.message}</div>`;
            return null;
        }
    }

    async function postData(url) {
        contentArea.innerHTML = '<div class="loading">Processing...</div>';
        try {
            const response = await fetch(url, { method: 'POST' });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const result = await response.json();
            if (!result.success) {
                throw new Error(result.error || 'API returned an error');
            }
            contentArea.innerHTML = `<div class="loading">${result.message}</div>`;
        } catch (error) {
            console.error('Post error:', error);
            contentArea.innerHTML = `<div class="error">Failed to perform action: ${error.message}</div>`;
        }
    }

    function renderComingSoon() {
        contentArea.innerHTML = `<div class="loading">Feature coming soon!</div>`;
    }

    async function renderProcessView() {
        const processes = await fetchData('http://127.0.0.1:8008/api/processes');
        if (!processes) return;

        let tableHtml = `
            <table>
                <thead>
                    <tr>
                        <th>PID</th>
                        <th>Process Name</th>
                        <th>Username</th>
                        <th>CPU %</th>
                        <th>Memory (MB)</th>
                        <th>Path</th>
                    </tr>
                </thead>
                <tbody>
        `;

        processes.forEach(p => {
            tableHtml += `
                <tr>
                    <td>${p.pid}</td>
                    <td>${p.name}</td>
                    <td>${p.username || 'N/A'}</td>
                    <td>${p.cpu_percent}</td>
                    <td>${(p.memory_mb).toFixed(2)}</td>
                    <td>${p.path || 'N/A'}</td>
                </tr>
            `;
        });

        tableHtml += '</tbody></table>';
        contentArea.innerHTML = tableHtml;
    }

    async function renderNetworkView() {
        const connections = await fetchData('http://127.0.0.1:8008/api/network');
        if (!connections) return;

        let tableHtml = `
            <table>
                <thead>
                    <tr>
                        <th>PID</th>
                        <th>Process Name</th>
                        <th>Local Address</th>
                        <th>Remote Address</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        `;

        connections.forEach(c => {
            const local_addr = c.laddr_ip && c.laddr_port ? `${c.laddr_ip}:${c.laddr_port}` : 'N/A';
            const remote_addr = c.raddr_ip && c.raddr_port ? `${c.raddr_ip}:${c.raddr_port}` : 'N/A';
            tableHtml += `
                <tr>
                    <td>${c.pid}</td>
                    <td>${c.process_name || 'N/A'}</td>
                    <td>${local_addr}</td>
                    <td>${remote_addr}</td>
                    <td>${c.status}</td>
                </tr>
            `;
        });

        tableHtml += '</tbody></table>';
        contentArea.innerHTML = tableHtml;
    }

    function renderDllView() {
        contentArea.innerHTML = '<div class="loading">Enter a Process ID (PID) to search for loaded DLLs.</div>';
    }

    function renderHandleView() {
        contentArea.innerHTML = '<div class="loading">Enter a Process ID (PID) to search for open handles.</div>';
    }

    function renderDumpView() {
        contentArea.innerHTML = '<div class="loading">Enter a Process ID (PID) to create a memory dump.</div>';
    }

    // Event Listeners
    dllSearchBtn.addEventListener('click', async () => {
        const pid = pidInput.value.trim();
        if (!pid || !/^\d+$/.test(pid)) {
            contentArea.innerHTML = `<div class="error">Please enter a valid numeric PID.</div>`;
            return;
        }
        
        const dlls = await fetchData(`http://127.0.0.1:8008/api/dlls/${pid}`);
        if (!dlls) return;

        let tableHtml = `
            <table>
                <thead>
                    <tr>
                        <th>Path</th>
                        <th>Description</th>
                        <th>Company</th>
                    </tr>
                </thead>
                <tbody>
        `;

        dlls.forEach(d => {
            tableHtml += `
                <tr>
                    <td>${d.path}</td>
                    <td>${d.description || 'N/A'}</td>
                    <td>${d.company || 'N/A'}</td>
                </tr>
            `;
        });

        tableHtml += '</tbody></table>';
        contentArea.innerHTML = tableHtml;
    });

    handleSearchBtn.addEventListener('click', async () => {
        const pid = handlePidInput.value.trim();
        if (!pid || !/^\d+$/.test(pid)) {
            contentArea.innerHTML = `<div class="error">Please enter a valid numeric PID.</div>`;
            return;
        }
        
        const handles = await fetchData(`http://127.0.0.1:8008/api/handles/${pid}`);
        if (!handles) return;

        let tableHtml = `
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Name</th>
                    </tr>
                </thead>
                <tbody>
        `;

        handles.forEach(h => {
            tableHtml += `
                <tr>
                    <td>${h.type}</td>
                    <td>${h.name}</td>
                </tr>
            `;
        });

        tableHtml += '</tbody></table>';
        contentArea.innerHTML = tableHtml;
    });

    dumpBtn.addEventListener('click', () => {
        const pid = dumpPidInput.value.trim();
        if (!pid || !/^\d+$/.test(pid)) {
            contentArea.innerHTML = `<div class="error">Please enter a valid numeric PID.</div>`;
            return;
        }
        postData(`http://127.0.0.1:8008/api/dump/${pid}`);
    });

    menuItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const viewName = e.currentTarget.dataset.view;
            switchView(viewName);
        });
    });

    refreshBtn.addEventListener('click', () => {
        if (views[currentView]) {
            views[currentView].render();
        }
    });

    // Initial load
    switchView('processes');
});
