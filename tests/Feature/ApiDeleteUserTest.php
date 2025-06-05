<?php

use Tests\TestCase;
use Illuminate\Support\Facades\DB;

class ApiDeleteUserTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        DB::statement('TRUNCATE TABLE users');
    }

    public function test_apiDeleteUser_validUsernameData_expectedResponse()
    {
        DB::table('users')->insert([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password')
        ]);

        $request = ['username' => 'test-username'];

        $response = $this->delete('/api/apiDeleteUser', $request);
        $response->assertJson([
            'success' => true,
            'message' => 'Profile deleted successfully.'
        ]);

        $this->assertDatabaseMissing('users', [
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password')
        ]);
    }

    public function test_apiDeleteUser_userNotFound_expectedResponse()
    {
        DB::table('users')->insert([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password')
        ]);

        $request = ['username' => 'invalid-user'];

        $response = $this->delete('/api/apiDeleteUser', $request);
        $response->assertJson([
            'success' => false,
            'message' => 'User not found.'
        ]);

        $response->assertStatus(404);
    }

    public function test_apiDeleteUser_missingRequiredData()
    {
        $response = $this->delete('/api/apiDeleteUser', []);
        $response->assertInvalid(['username']);
    }
}
