<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\UserInfo;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use OpenApi\Annotations as OA;

class UserInfoController extends Controller
{
    /**
     * @OA\Get(
     *      path="/users/{user_id}/info",
     *      operationId="getUserInfo",
     *      tags={"User Info"},
     *      summary="Get additional information for a user",
     *      description="Returns the bio and preferences for a specific user. Users can view their own info; admins can view any.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(
     *          name="user_id",
     *          in="path",
     *          description="UUID of the user",
     *          required=true,
     *          @OA\Schema(type="string", format="uuid")
     *      ),
     *      @OA\Response(response=200, description="Successful operation", @OA\JsonContent(ref="#/components/schemas/UserInfo")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Not authorized to view this info"),
     *      @OA\Response(response=404, description="User or UserInfo not found")
     * )
     */
    public function show(User $user) // Route model binding for User
    {
        /** @var User $authenticatedUser */
        $authenticatedUser = Auth::user();

        if ($authenticatedUser->iduser !== $user->iduser && $authenticatedUser->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. You are not authorized to view this information.'], 403);
        }

        $userInfo = $user->userInfo; // Access the hasOne relationship

        if (!$userInfo) {
            return response()->json(['message' => 'User information not found for this user.'], 404);
        }

        return response()->json($userInfo);
    }

    /**
     * @OA\Post(
     *      path="/users/{user_id}/info",
     *      operationId="storeOrUpdateUserInfo",
     *      tags={"User Info"},
     *      summary="Create or update additional information for a user",
     *      description="Creates or updates the bio and preferences for a specific user. Users can manage their own info; admins can manage any.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(
     *          name="user_id",
     *          in="path",
     *          description="UUID of the user",
     *          required=true,
     *          @OA\Schema(type="string", format="uuid")
     *      ),
     *      @OA\RequestBody(
     *          required=true,
     *          description="User info data",
     *          @OA\JsonContent(ref="#/components/schemas/UserInfoInput")
     *      ),
     *      @OA\Response(response=200, description="User info updated successfully", @OA\JsonContent(ref="#/components/schemas/UserInfo")),
     *      @OA\Response(response=201, description="User info created successfully", @OA\JsonContent(ref="#/components/schemas/UserInfo")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Not authorized to manage this info"),
     *      @OA\Response(response=404, description="User not found"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     * @OA\Put(
     *      path="/users/{user_id}/info",
     *      operationId="storeOrUpdateUserInfoPut",
     *      tags={"User Info"},
     *      summary="Create or update additional information for a user (PUT)",
     *      description="Creates or updates the bio and preferences for a specific user using PUT. Users can manage their own info; admins can manage any.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(name="user_id", in="path", description="UUID of the user", required=true, @OA\Schema(type="string", format="uuid")),
     *      @OA\RequestBody(required=true, description="User info data", @OA\JsonContent(ref="#/components/schemas/UserInfoInput")),
     *      @OA\Response(response=200, description="User info updated successfully", @OA\JsonContent(ref="#/components/schemas/UserInfo")),
     *      @OA\Response(response=201, description="User info created successfully", @OA\JsonContent(ref="#/components/schemas/UserInfo")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Not authorized to manage this info"),
     *      @OA\Response(response=404, description="User not found"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function storeOrUpdate(Request $request, User $user) // Route model binding for User
    {
        /** @var User $authenticatedUser */
        $authenticatedUser = Auth::user();

        if ($authenticatedUser->iduser !== $user->iduser && $authenticatedUser->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. You are not authorized to manage this information.'], 403);
        }

        $validator = Validator::make($request->all(), [
            'bio' => 'nullable|string|max:5000',
            'preferences' => 'nullable|array',
            'preferences.*' => 'sometimes|string|max:255', // Ensures each item in the array is a string
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $validatedData = $validator->validated();

        $userInfo = UserInfo::updateOrCreate(
            ['user_id' => $user->iduser], // Search condition
            $validatedData                 // Data to update or create with
        );

        $statusCode = $userInfo->wasRecentlyCreated ? 201 : 200;

        return response()->json($userInfo, $statusCode);
    }
}
