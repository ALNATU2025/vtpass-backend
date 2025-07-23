// controllers/authController.js
// ...
const loginUser = async (req, res) => {
    const { email, password } = req.body;
    // ...
    try {
        const user = await User.findOne({ email });

        // Now use the matchPassword method from the User model instance
        if (user && (await user.matchPassword(password))) { // <-- CHANGE THIS LINE
            res.json({
                _id: user.id,
                fullName: user.fullName,
                phone: user.phone,
                email: user.email,
                token: generateToken(user._id),
                message: 'Logged in successfully'
            });
        } else {
            res.status(400).json({ message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error during user login:', error);
        res.status(500).json({ message: 'Server error during login', error: error.message });
    }
};
// ...