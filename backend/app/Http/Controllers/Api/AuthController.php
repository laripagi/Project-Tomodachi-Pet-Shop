<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\RegisterUserRequest;
use App\Models\User;
use App\Models\Role;
use App\Traits\ApiResponse;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    use ApiResponse;

    /**
     * Login endpoint
     * 
     * POST /api/login
     * 
     * @param LoginRequest $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(LoginRequest $request)
    {
        $user = User::where('email', $request->email)->first();

        // Check if user exists and password is correct
        if (!$user || !Hash::check($request->password, $user->password)) {
            return $this->errorResponse(
                'Invalid email or password',
                401
            );
        }

        // Delete any existing tokens for this user to ensure only one active token
        $user->tokens()->delete();

        // Generate new token
        $token = $user->createToken('auth-token')->plainTextToken;

        return $this->successResponse([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role ? $user->role->name : null,
                'role_id' => $user->role_id,
            ],
            'token' => $token,
            'token_type' => 'Bearer',
        ], 'Login successful', 200);
    }

    /**
     * Register endpoint
     * 
     * POST /api/register
     * 
     * @param RegisterRequest $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(RegisterRequest $request)
    {
        // Get default role (kasir)
        $defaultRole = Role::where('name', 'kasir')->first();

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'role_id' => $defaultRole?->id,
        ]);

        $token = $user->createToken('auth-token')->plainTextToken;

        return $this->successResponse([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role ? $user->role->name : null,
                'role_id' => $user->role_id,
            ],
            'token' => $token,
            'token_type' => 'Bearer',
        ], 'Registration successful', 201);
    }

    /**
     * Register user endpoint (Owner only)
     * 
     * POST /api/auth/register-user
     * 
     * Only users with 'owner' role can register new admin or kasir users.
     * 
     * @param RegisterUserRequest $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function registerUser(RegisterUserRequest $request)
    {
        // Get the role by name
        $role = Role::where('name', $request->role)->first();

        if (!$role) {
            return $this->errorResponse(
                'Role not found',
                400
            );
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'role_id' => $role->id,
        ]);

        return $this->successResponse([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role ? $user->role->name : null,
                'role_id' => $user->role_id,
            ],
        ], 'User registered successfully', 201);
    }

    /**
     * Get current logged in user
     * 
     * GET /api/me
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function me(Request $request)
    {
        $user = $request->user();

        if (!$user) {
            return $this->errorResponse(
                'Unauthorized',
                401
            );
        }

        return $this->successResponse([
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'role' => $user->role ? $user->role->name : null,
            'role_id' => $user->role_id,
        ], 'User retrieved successfully', 200);
    }

    /**
     * Logout endpoint
     * 
     * POST /api/logout
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return $this->successResponse(null, 'Logout successful', 200);
    }

    /**
     * Refresh token endpoint
     * 
     * POST /api/refresh-token
     * 
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function refreshToken(Request $request)
    {
        $user = $request->user();

        if (!$user) {
            return $this->errorResponse(
                'Unauthorized',
                401
            );
        }

        // Delete old token
        $request->user()->currentAccessToken()->delete();

        // Generate new token
        $token = $user->createToken('auth-token')->plainTextToken;

        return $this->successResponse([
            'token' => $token,
            'token_type' => 'Bearer',
        ], 'Token refreshed successfully', 200);
    }
}
