Java.perform(function () {
    // Find the MainActivity class
    var MainActivity = Java.use('com.example.loginscreen.MainActivity');

    // Find the onClick method in the MainActivity class
    var onClick = MainActivity.onClick;

    // Intercept the onClick method
    onClick.implementation = function (view) {
        // Call the original onClick method
        this.onClick(view);

        // Retrieve entered username and password
        var username = this.editTextUsername.getText().toString();
        var password = this.editTextPassword.getText().toString();

        // Log the credentials
        console.log("Username: " + username);
        console.log("Password: " + password);
    };
});
