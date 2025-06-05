<?php 

use Tests\TestCase;
use Illuminate\Support\Facades\DB;

class ApiGetAuthenticatedUserTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        DB::statement('TRUNCATE TABLE users');
    }
    public function test_apiGetAuthenticatedUser_validData_expectedResponse()
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
        ])->get('/apiGetAuthenticatedUser');

        $response->assertJson([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username'
        ]);
    }

    public function test_apiGetAuthenticatedUser_invalidTokenData_expectedResponse()
    {
        DB::table('users')->insert([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password'),
            'api_token' => 'test-token'
        ]);

        $response = $this->withHeaders([
            'Authorization' => 'Bearer invalid-token'
        ])->get('/apiGetAuthenticatedUser');

        $response->assertJson([
            'message' => 'Unauthorized'
        ]);

        $response->assertStatus(401);
    }
}