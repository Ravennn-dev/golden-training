<?php

use Tests\TestCase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;

class ApiLoginTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        DB::statement('TRUNCATE TABLE users');
    }

    public function test_apiLogin_validData_expectedResponse()
    {
        DB::table('users')->insert([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password')
        ]);

        $request = [
            'username' => 'test-username',
            'password' => 'test-password'
        ];

        $response = $this->post('api/apiLogin', $request);

        $response->assertJson([
            'success' => true,
            'message' => 'Login successful',
            'user' => [
                'id' => 1,
                'name' => 'test-name',
                'username' => 'test-username'
            ]
        ]);
    }

    public function test_apiLogin_invalidPassword_expectedResponse()
    {
        DB::table('users')->insert([
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password')
        ]);

        $request = [
            'username' => 'test-username',
            'password' => 'test-pass'
        ];

        $response = $this->post('api/apiLogin', $request);

        $response->assertJson([
            'success' => false,
            'message' => 'Invalid credentials'
        ]);

        $response->assertStatus(401);
    }

    #[DataProvider('loginDataParams')]
    public function test_apiLogin_missingRequiredFields($parameter)
    {
        $request = [
            'username' => 'test-username',
            'password' => 'test-password'
        ];

        unset($request[$parameter]);

        $response = $this->post('/api/apiLogin', $request);
        $response->assertInvalid([$parameter]);
    }

    public static function loginDataParams()
    {
        return [
            ['username'],
            ['password']
        ];
    }
}
