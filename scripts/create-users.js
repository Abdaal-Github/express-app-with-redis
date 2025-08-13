const axios = require('axios');

async function createUsers(numUsers) {
    const ports = [3000, 3001]; // Session server (3000), JWT server (3001)

    for (let i = 1; i <= numUsers; i++) {
        const username = `Test User ${i}`;
        const password = `${i}@password@123`;

        try {
            // Send registration requests to both servers concurrently
            await Promise.all(
                ports.map(port =>
                    axios.post(`http://localhost:${port}/register`, {
                        username,
                        password
                    }).then(() => {
                        console.log(`Registered ${username} on port ${port}`);
                    }).catch(error => {
                        console.error(`Error registering ${username} on port ${port}:`, error.response?.data || error.message);
                        throw error; // Re-throw to catch in outer try-catch
                    })
                )
            );
        } catch (error) {
            // Continue to next user if registration fails for either server
            console.error(`Failed to register ${username} on one or more servers`);
        }
    }
    console.log(`Completed registration attempts for ${numUsers} users`);
}

createUsers(500); // Create 1000 users for testing