// auth-guard.js - Protects private routes in MedLedger

(function() {
    // Check if the user is authenticated
    // isAuthenticated is now globally available from api.js via window.isAuthenticated
    if (typeof window.isAuthenticated !== "function" || !window.isAuthenticated()) {
        console.warn("User not authenticated. Redirecting to sign in gateway...");
        
        // Find relative path to signin.html based on current location
        const path = window.location.pathname;
        let redirectPath = "signin.html";
        
        // Determine correct path based on where the page is located
        if (path.includes("/dashboard/") || 
            path.includes("/record_details/") || 
            path.includes("/confirm_account_deletion/")) {
            redirectPath = "../Sign_in_sign_up/signin.html";
        } else if (path.includes("/reset_access_password/") || 
                   path.includes("/set_new_password/")) {
            redirectPath = "../Sign_in_sign_up/signin.html";
        } else if (path.includes("/Sign_in_sign_up/")) {
            // If we're already in the sign_in_sign_up folder, stay there
            redirectPath = "signin.html";
        } else {
            // Default: go up one level and find signin.html
            redirectPath = "../Sign_in_sign_up/signin.html";
        }
        
        // Perform the redirect
        window.location.href = redirectPath;
        return;
    }
    
    // Optional: Log successful authentication check
    console.debug("User authenticated. Access granted to:", window.location.pathname);
    
    // Optional: Verify token is still valid by making a lightweight API call
    // This is a non-blocking check that doesn't block page rendering
    (async function verifyToken() {
        try {
            await window.apiRequest('GET', '/auth/me', null, true);
        } catch (e) {
            // If token is invalid, redirect to login
            if (e.message && (e.message.includes('401') || e.message.includes('expired') || e.message.includes('invalid'))) {
                console.warn("Token verification failed. Redirecting to login...");
                const path = window.location.pathname;
                let redirectPath = "../Sign_in_sign_up/signin.html";
                if (path.includes("/reset_access_password/") || path.includes("/set_new_password/")) {
                    redirectPath = "../Sign_in_sign_up/signin.html";
                }
                window.location.href = redirectPath;
            }
        }
    })();
    
})();