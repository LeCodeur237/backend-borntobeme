<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;
use OpenApi\Annotations as OA;

/**
 * @OA\Info(
 *      version="1.0.0",
 *      title="BornToMe API Documentation",
 *      description="API documentation for the BornToMe Blog application. This API allows for user authentication, article management, and commenting functionalities.",
 *      @OA\Contact(
 *          email="judek@example.com"
 *      ),
 *      @OA\License(
 *          name="Apache 2.0",
 *          url="http://www.apache.org/licenses/LICENSE-2.0.html"
 *      )
 * )
 *
 * @OA\Server(
 *      url=L5_SWAGGER_CONST_HOST,
 *      description="BornToMe API Server"
 * )
 *
 * @OA\SecurityScheme(
 *     securityScheme="bearerAuth",
 *     type="http",
 *     scheme="bearer",
 *     bearerFormat="JWT",
 *     description="Enter token in format (Bearer <token>)"
 * )
 *
 * @OA\Tag(name="Authentication", description="User authentication endpoints (register, login, logout)")
 * @OA\Tag(name="Users", description="User related endpoints (e.g., fetching authenticated user details)")
 * @OA\Tag(name="Articles", description="Article management endpoints (CRUD operations for articles)")
 * @OA\Tag(name="Comments", description="Comment management endpoints (CRUD operations for comments - to be implemented)")
 *
 * @OA\Schema(
 *   schema="ValidationError",
 *   type="object",
 *   title="Validation Error",
 *   @OA\Property(property="message", type="string", example="The given data was invalid."),
 *   @OA\Property(property="errors", type="object", example={"field_name": {"Error message for this field."}})
 * )
 */
class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;
}
