async function loadVersionSelector(baseUrl, targetElementId, legacyVersion = null, additionalVersions = []) {
    const targetElement = document.getElementById(targetElementId);
    if (!targetElement) return;

    // Create container
    const container = document.createElement('div');
    container.className = 'version-selector';

    // Style for the version links
    const style = document.createElement('style');
    style.textContent = `
        .version-selector {
            margin: 1rem 0;
            display: flex;
            gap: 0.5rem;
            align-items: center;
            flex-wrap: wrap;
        }
        .version-link {
            padding: 0.25rem 0.75rem;
            text-decoration: none;
            border-radius: 15px;
            font-size: 0.9rem;
            transition: background-color 0.2s;
        }
        .version-link.latest {
            color: #ff8c00;
            border: 1px solid #ff8c00;
        }
        .version-link.regular {
            color: #666;
            border: 1px solid #666;
        }
        .version-link.legacy {
            color: #2d5b88;
            border: 1px solid #2d5b88;
        }
        .version-link:hover {
            background-color: #f0f0f0;
        }
        .version-dropdown {
            position: relative;
            display: inline-block;
        }
        .version-dropdown-content {
            display: none;
            position: absolute;
            background-color: #fff;
            min-width: 160px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
            z-index: 1;
            border-radius: 4px;
            padding: 0.5rem 0;
        }
        .version-dropdown:hover .version-dropdown-content {
            display: block;
        }
        .version-dropdown-btn {
            padding: 0.25rem 0.75rem;
            background: none;
            border: 1px solid #666;
            border-radius: 15px;
            color: #666;
            cursor: pointer;
            font-size: 0.9rem;
            font-family: inherit;
        }
        .version-dropdown-content a {
            color: #666;
            padding: 0.5rem 1rem;
            text-decoration: none;
            display: block;
            font-size: 0.9rem;
        }
        .version-dropdown-content a:hover {
            background-color: #f0f0f0;
        }
        .version-divider {
            color: #666;
            margin: 0 0.5rem;
            font-size: 0.9rem;
        }
    `;
    document.head.appendChild(style);

    try {
        let versions = [];
        
        try {
            // Attempt to fetch versions.json with cache-busting
            const timestamp = new Date().getTime();
            const response = await fetch(`${baseUrl}/versions.json?t=${timestamp}`);
            if (response.ok) {
                const fetchedVersions = await response.json();
                versions = [...fetchedVersions];
            }
        } catch (fetchError) {
            console.warn('Failed to fetch versions.json:', fetchError);
        }

        // Mix in additional versions if provided
        if (additionalVersions.length > 0) {
            // Create a map of existing versions to avoid duplicates
            const versionMap = new Map(versions.map(v => [v.version, v]));
            
            // Add or update with additional versions
            additionalVersions.forEach(v => {
                versionMap.set(v.version, v);
            });
            
            versions = Array.from(versionMap.values());
        }

        // For additional products (not auth/recursor/dnsdist), show at least a "latest" link
        const isAdditionalProduct = !baseUrl.endsWith('/authoritative') && 
                                  !baseUrl.endsWith('/recursor') && 
                                  !baseUrl.includes('dnsdist.org');
        if (versions.length === 0 && isAdditionalProduct) {
            const latestLink = document.createElement('a');
            latestLink.href = `${baseUrl}/latest/`;
            latestLink.textContent = 'latest';
            latestLink.className = 'version-link latest';
            container.appendChild(latestLink);
        }

        // Only proceed with version list if we have versions to display
        if (versions.length > 0) {
            // Sort versions using semver
            versions.sort((a, b) => {
                const [aMajor, aMinor, aPatch] = a.version.split('.').map(Number);
                const [bMajor, bMinor, bPatch] = b.version.split('.').map(Number);
                
                if (aMajor !== bMajor) return bMajor - aMajor;
                if (aMinor !== bMinor) return bMinor - aMinor;
                return bPatch - aPatch;
            });

            // Check if any version is marked as latest
            const hasLatestVersion = versions.some(v => v.aliases && v.aliases.includes('latest'));

            // Add version links
            versions.forEach((version, index) => {
                if (index < 3) {
                    const link = document.createElement('a');
                    link.href = `${baseUrl}/${version.version}/`;
                    link.textContent = version.version;
                    // If no version is marked as latest, mark the newest version (index 0) as latest
                    const isLatest = version.aliases?.includes('latest') || (!hasLatestVersion && index === 0);
                    link.className = `version-link ${isLatest ? 'latest' : 'regular'}`;
                    container.appendChild(link);
                }
            });

            // Add dropdown for additional versions if needed
            if (versions.length > 3) {
                const dropdown = document.createElement('div');
                dropdown.className = 'version-dropdown';
                
                const dropdownBtn = document.createElement('button');
                dropdownBtn.className = 'version-dropdown-btn';
                dropdownBtn.textContent = 'More versions';
                
                const dropdownContent = document.createElement('div');
                dropdownContent.className = 'version-dropdown-content';

                versions.slice(3).forEach(version => {
                    const link = document.createElement('a');
                    link.href = `${baseUrl}/${version.version}/`;
                    link.textContent = version.version;
                    dropdownContent.appendChild(link);
                });

                dropdown.appendChild(dropdownBtn);
                dropdown.appendChild(dropdownContent);
                container.appendChild(dropdown);
            }

            // Add divider and legacy version link if provided
            if (legacyVersion) {
                const divider = document.createElement('span');
                divider.textContent = '|';
                divider.className = 'version-divider';
                container.appendChild(divider);

                const legacyLink = document.createElement('a');
                legacyLink.href = legacyVersion.url;
                legacyLink.textContent = legacyVersion.label;
                legacyLink.className = 'version-link legacy';
                container.appendChild(legacyLink);
            }
        } else if (legacyVersion) {
            // If no versions but we have a legacy version, just show that
            const legacyLink = document.createElement('a');
            legacyLink.href = legacyVersion.url;
            legacyLink.textContent = legacyVersion.label;
            legacyLink.className = 'version-link legacy';
            container.appendChild(legacyLink);
        }

        // Only append the container if we have something to show
        if (container.children.length > 0) {
            targetElement.appendChild(container);
        }
    } catch (error) {
        console.warn('Failed to load version selector:', error);
        // If everything fails but we have a legacy version, show it
        if (legacyVersion) {
            const legacyLink = document.createElement('a');
            legacyLink.href = legacyVersion.url;
            legacyLink.textContent = legacyVersion.label;
            legacyLink.className = 'version-link legacy';
            container.appendChild(legacyLink);
            targetElement.appendChild(container);
        }
    }
} 