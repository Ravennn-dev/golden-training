<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Repositories\UserRepository;

class UserController extends Controller
{
    public function __construct(private UserRepository $repository) {}

    public function apiRegister(Request $request)
    {
        $fields = $request->validate([
            'name' => 'required',
            'username' => 'required',
            'password' => 'required',
        ]);

        $userData = $this->repository->getUserByUsername($fields['username']);

        if ($userData) {
            return response()->json([
                'message' => 'Username already taken'
            ], 409);
        }

        $user = $this->repository->createUser($request->name, $request->username, $request->password);

        return response()->json([
            'message' => 'User Registered Successfully',
            'user' => [
                'name' => $user->name,
                'username' => $user->username
            ]
        ], 201);
    }

    public function apiLogin(Request $request)
    {
        // credentials
        $request->validate([
            'username' => 'required',
            'password' => 'required'
        ]);

        $user = $this->repository->getUserByUsernamePassword($request->username, $request->password);

        if (!$user) {

            return response()->json([
                'success' => false,
                'message' => 'Invalid credentials'
            ], 401);
        }

        $apiToken = $this->repository->assignApiTokenToUser($user->id);

        return response()->json([
            'success' => true,
            'message' => 'Login successful',
            'api_token' => $apiToken,
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'username' => $user->username
            ]
        ]);
    }

    public function apiGetAuthenticatedUser(Request $request)
    {
        $apiToken = $request->bearerToken();
        $user = $this->repository->authenticateToken($apiToken);

        // if(is_null($user) === false) {
        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        return response()->json([
            'id' => $user->id,
            'name' => $user->name,
            'username' => $user->username,
        ]);
    }

    public function apiUpdate(Request $request)
    {
        $apiToken = $request->bearerToken();
        $user = $this->repository->authenticateToken($apiToken);

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        $validatedData = $request->validate([
            'name' => 'sometimes',
            'username' => 'sometimes',
            'password' => 'nullable',
        ]);

        if (isset($validatedData['username'])) {
            $existingUser = $this->repository->getUserByUsername($validatedData['username']);

            if ($existingUser && $existingUser->id !== $user->id) {
                return response()->json(['error' => 'Username already taken.'], 422);
            }
        }

        $updateData = [];

        if ($request->filled('name')) {
            $updateData['name'] = $validatedData['name'];
        }

        if ($request->filled('username')) {
            $updateData['username'] = $validatedData['username'];
        }

        if ($request->filled('password')) {
            $updateData['password'] = md5($validatedData['password']);
        }

        if (!empty($updateData)) {
            $this->repository->updateUser($user->id, $updateData);
        }

        $updatedUser = $this->repository->getUserById($user->id);

        return response()->json([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => $updatedUser->name,
                'username' => $updatedUser->username,
            ]
        ]);
    }

    public function apiDeleteUser(Request $request)
    {
        $request->validate([
            'username' => 'required',
        ]);

        $user = $this->repository->getUserByUsername($request->username);

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'User not found.',
            ], 404);
        }

        $this->repository->deleteUser($user->id);

        return response()->json([
            'success' => true,
            'message' => 'Profile deleted successfully.',
        ]);
    }

    public function apiLogout(Request $request)
    {
        $apiToken = $request->bearerToken();
        $user = $this->repository->authenticateToken($apiToken);

        if ($user) {
            $this->repository->clearApiToken($user->id);
        }

        return response()->json(['message' => 'You have been logged out.']);
    }
}
