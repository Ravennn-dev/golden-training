<?php

use Tests\TestCase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;

class ApiRegisterTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        DB::statement('TRUNCATE TABLE users');
    }

    public function test_apiRegister_validData_expectedResponse()
    {
        $request = [
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => 'test-password',
        ];

        $response = $this->post('/api/apiRegister', $request);

        $response->assertJson([
            'message' => 'User Registered Successfully',
            'user' => [
                'name' => 'test-name',
                'username' => 'test-username'
            ]
        ]);

        $response->assertStatus(201);

        $this->assertDatabaseHas('users', [
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password')
        ]);
    }

    public function test_apiRegister_duplicateUsername_expectedResponse()
    {
        DB::table('users')->insert([
            'name' => 'test-name',
            'username' => 'existing-username',
            'password' => md5('test-password')
        ]);

        $request = [
            'name' => 'test',
            'username' => 'existing-username',
            'password' => 'password',
        ];

        $response = $this->post('/api/apiRegister', $request);

        $response->assertJson([
            'message' => 'Username already taken'
        ]);

        $response->assertStatus(409);
    }

    #[DataProvider('registerDataParams')]
    public function test_apiRegister_missingRequiredFields($parameter)
    {
        $request = [
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => 'test-password'
        ];

        unset($request[$parameter]);

        $response = $this->post('/api/apiRegister', $request);
        $response->assertInvalid([$parameter]);
    }

    public static function registerDataParams()
    {
        return [
            ['name'],
            ['username'],
            ['password']
        ];
    }
}
