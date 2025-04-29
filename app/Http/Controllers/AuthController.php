<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        // Validate the request
        // $validated = $request->validate([
        //     'name' => 'required|string|max:255',
        //     'email' => 'required|string|email|max:255|unique:users',
        //     'password' => 'required|string|min:8|confirmed',
        // ]);

        $validated = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        if ($validated->fails()) {
            return response()->json($validated->errors(), 403);
        }
        try{

            $user = User::create([
                'name' => $request->input('name'),
                'email' => $request->input('email'),
                'password' => Hash::make($request->input('password')),
            ]);

            $token = $user->createToken('auth_token')->plainTextToken;

            // Return the user and token
            return response()->json([
                'user' => $user,
                'token' => $token,], 200);

        }catch(\Exception $exception){
            return response()->json(['error' => $exception->getMessage()], 403);
        }


    }

    public function login(Request $request){
        $validated = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string|min:8',
        ]);

        if($validated->fails()){
            return response()->json($validated->errors(), 403);
        }

        $credentials = ['email'=>$request->email, 'password'=>$request->password];

        try{

            if(!auth()->attempt($credentials)){
                return response()->json(['error' => 'Invalid credentials'], 403);
            }

            $user = User::where('email', $request->email)->firstOrFail();

            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'user' => $user,
                'token' => $token,
            ], 200);
        }catch(\Exception $exception){
            return response()->json(['error' => $exception->getMessage()], 403);
        }
    }


    public function logout(Request $request){
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Logged out successfully'], 200);

    }
}
