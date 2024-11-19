<?php

namespace App\Http\Controllers;



use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthenticationController extends Controller
{
    // Register a new user
    public function register(Request $request)
    {
        // Validate incoming request
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
            'role' => 'nullable|string|in:user,admin',
        ], [
            'name.required' => 'The name field is required.',
            'email.required' => 'The email field is required.',
            'email.email' => 'The email must be a valid email address.',
            'email.unique' => 'This email is already taken.',
            'password.required' => 'The password field is required.',
            'password.min' => 'The password must be at least 8 characters.',
            'password.confirmed' => 'The password confirmation does not match.',
            'role.in' => 'The role must be either "user" or "admin".',
        ]);

        // Set default role to 'user' if not provided
        $role = $validated['role'] ?? 'user';

        // Create the user with validated data
        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => bcrypt($validated['password']),
            'role' => $role,
        ]);

        // Return a success response with 201 status code
        return response()->json([
            'message' => 'User registered successfully.',
            'user' => [
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role,
            ],
        ], 201);  // 201 Created status code
    }

    // Login user and generate JWT token
    public function login(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        $credentials = $validated;

        if ($token = JWTAuth::attempt($credentials)) {
            // return the role along with the token
            $user = JWTAuth::user();
            return response()->json([
                'token' => $token,
                'role' => $user->role,
            ]);
        }

        return response()->json(['error' => 'Unauthorized'], 401);
    }

    // Get the currently authenticated user
    public function loginUser()
    {
        $user = JWTAuth::user();

        return response()->json($user);
    }

    // Logout and invalidate token
    public function logout()
    {
        JWTAuth::invalidate(JWTAuth::getToken());

        return response()->json(['message' => 'Successfully logged out']);
    }
}
