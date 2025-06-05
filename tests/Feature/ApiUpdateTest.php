<?php

use Tests\TestCase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;

class ApiUpdateTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        DB::statement('TRUNCATE TABLE users');
    }

    public function test_apiUpdate_validData_expectedResponse()
    {
        DB::table('users')->insert([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password'),
            'api_token' => 'test-token'
        ]);

        $request = [
            'name' => 'new-name',
            'username' => 'new-username',
            'password' => 'new-password'
        ];

        $response = $this->withHeaders([
            'Authorization' => 'Bearer test-token'
        ])->patch('/api/apiUpdate', $request);

        $response->assertJson([
            'success' => true,
            'message' => 'User updated successfully',
            'user' => [
                'name' => 'new-name',
                'username' => 'new-username',
            ]
        ]);

        $this->assertDatabaseMissing('users', [
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password'),
        ]);

        $this->assertDatabaseHas('users', [
            'name' => 'new-name',
            'username' => 'new-username',
            'password' => md5('new-password')
        ]);
    }

    public function test_apiUpdate_invalidTokenData_expectedResponse()
    {
        DB::table('users')->insert([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password'),
            'api_token' => 'test-token'
        ]);

        $request = [
            'name' => 'new-name',
            'username' => 'new-username',
            'password' => 'new-password'
        ];

        $response = $this->withHeaders([
            'Authorization' => 'Bearer invalid-token'
        ])->patch('/api/apiUpdate', $request);

        $response->assertJson([
            'message' => 'Unauthorized'
        ]);

        $response->assertStatus(401);

        $this->assertDatabaseMissing('users', [
            'name' => 'new-name',
            'username' => 'new-username',
            'password' => 'new-password'
        ]);
    }

    public function test_apiUpdate_duplicateUsername_expectedResponse()
    {
        //user
        DB::table('users')->insert([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password'),
            'api_token' => 'test-token'
        ]);

        //existing user data
        DB::table('users')->insert([
            'id' => 2,
            'name' => 'user-name',
            'username' => 'taken-username',
            'password' => md5('user-password'),
            'api_token' => 'user-token'
        ]);

        $request = [
            'name' => 'new-name',
            'username' => 'taken-username',
            'password' => 'new-password'
        ];

        $response = $this->withHeaders([
            'Authorization' => 'Bearer test-token'
        ])->patch('/api/apiUpdate', $request);

        $response->assertJson([
            'error' => 'Username already taken.'
        ]);
        $response->assertStatus(422);

        $this->assertDatabaseHas('users', [
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password'),
            'api_token' => 'test-token'
        ]);

        $this->assertDatabaseMissing('users', [
            'name' => 'new-name',
            'username' => 'taken-username',
            'password' => 'new-password'
        ]);
    }

    #[DataProvider('updateDataParams')]
    public function test_apiUpdate_partialUpdates($parameter)
    {
        DB::table('users')->insert([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password'),
            'api_token' => 'test-token'
        ]);

        $response = $this->withHeaders([
            'Authorization' => 'Bearer test-token'
        ])->patch('/api/apiUpdate', $parameter);

        $response->assertJson([
            'success' => true,
            'message' => 'User updated successfully',
        ]);

        if (isset($parameter['password'])) {
            $parameter['password'] = md5($parameter['password']);
        }

        $this->assertDatabaseMissing('users', [
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password')
        ]);

        $this->assertDatabaseHas('users', array_merge(['id' => 1], $parameter));
    }

    public static function updateDataParams()
    {
        return [
            [['name' => 'new-name']],
            [['username' => 'new-username']],
            [['password' => 'new-password']],
            [[
                'name' => 'new-name',
                'username' => 'new-username'

            ]],
            [[
                'username' => 'new-username',
                'password' => 'new-password',
            ]],
            [[
                'name' => 'new-name',
                'password' => 'new-password',
            ]],
            [[
                'name' => 'new-name',
                'username' => 'new-username',
                'password' => 'new-password',
            ]]
        ];
    }
}
