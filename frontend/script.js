document.addEventListener('DOMContentLoaded', () => {
    const API_BASE_URL = 'https://vibelist-playlistsuggester.onrender.com';
    const token = localStorage.getItem('vibelist_token');

    const authContainer = document.getElementById('auth-container');
    const playlistForm = document.getElementById('playlist-form');
    const resultsSection = document.getElementById('results-section');
    const playlistResults = document.getElementById('playlist-results');
    const savedPlaylistsSection = document.getElementById('saved-playlists-section');
    const savedPlaylistsResults = document.getElementById('saved-playlists-results');

    const checkAuthState = async () => {
        if (!token) {
            updateUIForLoggedOutUser();
            return;
        }
        try {
            const response = await fetch(`${API_BASE_URL}/users/me/`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (response.ok) {
                const user = await response.json();
                updateUIForLoggedInUser(user.email);
                fetchSavedPlaylists();
            } else {
                logout();
            }
        } catch (error) {
            console.error('Auth check failed:', error);
            updateUIForLoggedOutUser();
        }
    };

    const updateUIForLoggedInUser = (email) => {
        savedPlaylistsSection.classList.remove('hidden');
        authContainer.innerHTML = `
            <div class="flex items-center gap-4">
                <span class="text-gray-300">Welcome, ${email}</span>
                <button id="logout-btn" class="bg-red-500 hover:bg-red-600 font-semibold py-2 px-4 rounded-lg transition-colors">Logout</button>
            </div>
        `;
        document.getElementById('logout-btn').addEventListener('click', logout);
    };

    const updateUIForLoggedOutUser = () => {
        savedPlaylistsSection.classList.add('hidden');
        authContainer.innerHTML = `
            <a href="login.html" class="bg-gray-700 hover:bg-gray-600 font-semibold py-2 px-4 rounded-lg transition-colors">Login</a>
            <a href="register.html" class="bg-green-500 hover:bg-green-600 font-semibold py-2 px-4 rounded-lg transition-colors ml-2">Register</a>
        `;
    };

    const logout = () => {
        localStorage.removeItem('vibelist_token');
        updateUIForLoggedOutUser();
    };

    playlistForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const mood = document.getElementById('mood').value;
        const genre = document.getElementById('genre').value;
        const language = document.getElementById('language').value;

        playlistResults.innerHTML = '<p class="text-center col-span-full">Finding your vibe...</p>';
        resultsSection.classList.remove('hidden');

        try {
            const response = await fetch(`${API_BASE_URL}/suggest`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mood, genre, language }),
            });
            if (!response.ok) throw new Error('Network response was not ok');
            const data = await response.json();
            displayPlaylists(data.playlists, playlistResults, true);
        } catch (error) {
            console.error('Error fetching playlists:', error);
            playlistResults.innerHTML = '<p class="text-center text-red-400 col-span-full">Could not fetch playlists.</p>';
        }
    });
    
    const displayPlaylists = (playlists, container, showSaveButton) => {
        container.innerHTML = '';
        if (!playlists || playlists.length === 0) {
            container.innerHTML = '<p class="text-center col-span-full">No playlists to show.</p>';
            return;
        }
        playlists.forEach(playlist => {
            const saveButtonHTML = showSaveButton && token ? `
                <button class="save-btn mt-2 w-full text-center bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded-lg"
                        data-name="${playlist.name}" 
                        data-spotify_url="${playlist.spotify_url}" 
                        data-image_url="${playlist.image_url || ''}"
                        data-owner="${playlist.owner || 'Unknown'}">
                    Save Playlist
                </button>
            ` : '';
            const card = `
                <div class="bg-gray-800 rounded-lg overflow-hidden shadow-lg transform hover:-translate-y-2 transition-transform duration-300">
                    <img src="${playlist.image_url || 'https://picsum.photos/seed/placeholder/400/400'}" alt="${playlist.name}" class="w-full h-48 object-cover">
                    <div class="p-4">
                        <h3 class="font-bold text-lg truncate" title="${playlist.name}">${playlist.name}</h3>
                        <p class="text-gray-400 text-sm mb-4">By ${playlist.owner || 'Unknown'}</p>
                        <a href="${playlist.spotify_url}" target="_blank" class="block w-full text-center bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 rounded-lg">
                            Listen on Spotify
                        </a>
                        ${saveButtonHTML}
                    </div>
                </div>`;
            container.insertAdjacentHTML('beforeend', card);
        });
    };

    const fetchSavedPlaylists = async () => {
        if (!token) return;
        try {
            const response = await fetch(`${API_BASE_URL}/users/me/playlists`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (response.ok) {
                const saved = await response.json();
                displayPlaylists(saved, savedPlaylistsResults, false);
            }
        } catch (error) {
            console.error('Could not fetch saved playlists:', error);
        }
    };
    
    resultsSection.addEventListener('click', async (event) => {
        if (event.target && event.target.classList.contains('save-btn')) {
            const button = event.target;
            const playlistData = {
                name: button.dataset.name,
                spotify_url: button.dataset.spotify_url,
                image_url: button.dataset.image_url,
            };
            try {
                const response = await fetch(`${API_BASE_URL}/users/me/playlists`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify(playlistData)
                });
                if (response.ok) {
                    alert('Playlist saved!');
                    fetchSavedPlaylists();
                } else {
                    const error = await response.json();
                    alert(`Could not save playlist: ${error.detail}`);
                }
            } catch (error) {
                console.error('Error saving playlist:', error);
            }
        }
    });

    checkAuthState();

});

