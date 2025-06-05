<?php

use Tests\TestCase;
use Illuminate\Support\Facades\DB;

class ApiLogoutTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        DB::statement('TRUNCATE TABLE users');
    }

    public function test_apiLogout_validTokenData_expectedResponse()
    {
        DB::table('users')->insert([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password'),
            'api_token' => 'test-token'
        ]);

        $response = $this->post('api/apiLogout')
            ->withHeaders([
                'Authorization' => 'Bearer test-token'
            ]);

        $response->assertJson([
            'message' => 'You have been logged out.'
        ]);

        $this->assertDatabaseMissing('users', [
            'api_token' => 'test-token'
        ]);

        $this->assertDatabaseHas('users', [
            'id' => 1,
            'api_token' => null
        ]);
    }

    public function test_apiLogout_invalidDataToken_expectedResponse()
    {
        DB::table('users')->insert([
            'id' => 1,
            'name' => 'test-name',
            'username' => 'test-username',
            'password' => md5('test-password'),
            'api_token' => 'test-token'
        ]);

        $this->post('api/apiLogout')
            ->withHeaders([
                'Authorization' => 'Bearer invalid-token'
            ]);

        $this->assertDatabaseHas('users', [
            'api_token' => 'test-token'
        ]);
    }
}
