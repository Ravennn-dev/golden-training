<?php

namespace App\Repositories;

use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class UserRepository //Repository is only for DB queries
{
    public function getUserByUsername(string $username): ?object
    {
        return DB::table('users')
            ->where('username', $username)
            ->first();
    }

    public function getUserByUsernamePassword(string $username, string $password): ?object
    {
        return DB::table('users')
            ->where('username', $username)
            ->where('password', md5($password))
            ->first();
    }

    public function getUserByName(string $name): ?object
    {
        return DB::table('users')
            ->where('name', $name);
    }

    public function getUserById(int $id): ?User
    {
        return DB::table('users')
            ->find($id);
    }

    public function createUser(string $name, string $username, string $password): ?object
    {
        $inserted = DB::table('users')
            ->insert([
                'name' => $name,
                'username' => $username,
                'password' => md5($password)
            ]);

        return (object) [
            'id' => $inserted,
            'name' => $name,
            'username' => $username
        ];
    }

    public function authenticateToken(string $api_token)
    {
        return DB::table('users')
            ->where('api_token', $api_token)
            ->first();
    }

    public function updateUser(int $userId, array $data): bool
    {
        return DB::table('users')
            ->where('id', $userId)
            ->update($data) > 0;
    }

    public function deleteUser(int $id): bool
    {
        return DB::table('users')
            ->where('id', $id)
            ->delete() > 0;
    }

    public function saveUserData(string $api_token): bool
    {
        $user = DB::table('users')->where('api_token', $api_token)->first();

        if ($user && isset($user->data)) {
            return DB::table('users')
                ->where('api_token', $api_token)
                ->update(json_decode($user->data, true)) > 0;
        }
        return false;
    }

    public function clearApiToken(int $id): bool
    {
        return DB::table('users')
            ->where('id', $id)
            ->update(['api_token' => null]) > 0;
    }

    public function assignApiTokenToUser(int $id): string
    {
        $api_token = Str::random(64);
        DB::table('users')
            ->where('id', $id)
            ->update(['api_token' => $api_token]);
        return $api_token;
    }
}
