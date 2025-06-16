<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Article;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\Validator; // Added this line
use Illuminate\Validation\Rule; // Added this line
use OpenApi\Annotations as OA; // Required for OA annotations

class ArticleController extends Controller
{
    /**
     * @OA\Get(
     *      path="/articles",
     *      operationId="getArticlesList",
     *      tags={"Articles"},
     *      summary="Get list of articles (Publicly accessible)",
     *      description="Returns a paginated list of articles. This endpoint is publicly accessible.",
     *      @OA\Parameter(
     *          name="page",
     *          in="query",
     *          description="Page number",
     *          required=false,
     *          @OA\Schema(type="integer", default=1)
     *      ),
     *      @OA\Parameter(
     *          name="per_page",
     *          in="query",
     *          description="Number of items per page",
     *          required=false,
     *          @OA\Schema(type="integer", default=15)
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Successful operation",
     *          @OA\JsonContent(
     *              type="object",
     *              @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/Article")),
     *              @OA\Property(property="links", type="object"),
     *              @OA\Property(property="meta", type="object")
     *          )
     *      ),
     *      @OA\Response(response=400, description="Bad Request (e.g., invalid pagination parameters)")
     * )
     * Display a listing of the resource.
     */
    public function index()
    {
        // Future enhancement: Admins might see all statuses, regular users only 'published'.
        $articles = Article::with('author')->latest()->paginate(); // Default pagination, ordered by latest

        return response()->json($articles);
    }

    /**
     * @OA\Post(
     *      path="/articles",
     *      operationId="storeArticle",
     *      tags={"Articles"},
     *      summary="Create a new article",
     *      description="Creates a new article and returns the created article. The authenticated user becomes the author.",
     *      security={{"bearerAuth":{}}},
     *      @OA\RequestBody(
     *          required=true,
     *          description="Article data",
     *
     *         @OA\JsonContent(ref="#/components/schemas/ArticleInput")
     *      ),
     *      @OA\Response(
     *          response=201,
     *          description="Article created successfully",
     *          @OA\JsonContent(ref="#/components/schemas/Article")
     *      ),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=422, description="Validation error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        // Validate the request data
        $validator = Validator::make($request->all(), [
            'title' => 'required|string|max:255',
            'category' => 'required|string|max:255',
            'content' => 'required|string',
            'link_picture' => 'nullable|string|url|max:255',
            'status' => ['nullable', 'string', Rule::in(['draft', 'published', 'archived'])],
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        // Ensure the authenticated user is the author
        $user = Auth::user();

        // Create the article
        $article = Article::create([
            'title' => $request->title,
            'category' => $request->category,
            'content' => $request->content,
            'user_id' => $user->iduser, // Assign the authenticated user's ID
            'link_picture' => $request->link_picture,
            'status' => $request->status ?? 'draft', // Default to draft if not provided
        ]);

        // Load the author relationship for the response
        $article->load('author');

        return response()->json($article, 201);
    }

    /**
     * @OA\Get(
     *      path="/articles/{id}",
     *      operationId="getArticleById",
     *      tags={"Articles"},
     *      summary="Get article by ID (Publicly accessible)",
     *      description="Returns a single article. This endpoint is publicly accessible.",
     *      @OA\Parameter(
     *          name="id",
     *          in="path",
     *          description="ID of article to return",
     *          required=true,
     *          @OA\Schema(type="integer")
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Successful operation",
     *          @OA\JsonContent(ref="#/components/schemas/Article")
     *      ),
     *      @OA\Response(response=404, description="Article not found")
     * )
     * Display the specified resource.
     */
    public function show(string $id)
    {
        $article = Article::with('author')->find($id);

        if (!$article) {
            return response()->json(['message' => 'Article not found'], 404);
        }

        return response()->json($article);
    }

    /**
     * @OA\Put(
     *      path="/articles/{id}",
     *      operationId="updateArticle",
     *      tags={"Articles"},
     *      summary="Update an existing article",
     *      description="Updates an article. Regular users can only update their own articles. Admins can update any article.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(
     *          name="id",
     *          in="path",
     *          description="ID of article to update",
     *          required=true,
     *          @OA\Schema(type="integer")
     *      ),
     *      @OA\RequestBody(
     *          required=true,
     *          description="Article data to update",
     *          @OA\JsonContent(ref="#/components/schemas/ArticleInput")
     *      ),
     *      @OA\Response(
     *          response=200,
 *          description="Article updated successfully",
 *          @OA\JsonContent(ref="#/components/schemas/Article")
 *      ),
 *      @OA\Response(response=401, description="Unauthenticated"),
 *      @OA\Response(response=403, description="Forbidden - User does not own this article or lacks permission"),
 *      @OA\Response(response=404, description="Article not found"),
 *      @OA\Response(response=422, description="Validation error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
 * )
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        $article = Article::find($id);

        if (!$article) {
            return response()->json(['message' => 'Article not found'], 404);
        }

        $authenticatedUser = Auth::user();

        // Authorization: User must be the author OR an admin to update
        if ($authenticatedUser->iduser !== $article->user_id && $authenticatedUser->role !== 'admin') {
            return response()->json(['message' => 'You do not have permission to update this article'], 403);
        }

        // Validate the request data
        $validator = Validator::make($request->all(), [
            'title' => 'required|string|max:255',
            'category' => 'required|string|max:255',
            'content' => 'required|string',
            'link_picture' => 'nullable|string|url|max:255',
            'status' => ['nullable', 'string', Rule::in(['draft', 'published', 'archived'])],
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        // Update the article
        $article->update($request->all());

        // Load the author relationship for the response
        $article->load('author');

        return response()->json($article);
    }

    /**
     * @OA\Delete(
     *      path="/articles/{id}",
     *      operationId="deleteArticle",
     *      tags={"Articles"},
     *      summary="Delete an article",
     *      description="Deletes a specific article by ID. Regular users can only delete their own articles. Admins can delete any article.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(
     *          name="id",
     *          in="path",
     *          description="ID of article to delete",
     *          required=true,
     *          @OA\Schema(type="integer")
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Article deleted successfully",
     *          @OA\JsonContent(@OA\Property(property="message", type="string", example="Article deleted successfully"))
     *      ),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - User does not own this article or lacks permission"),
     *      @OA\Response(response=404, description="Article not found")
     * )
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        $article = Article::find($id);

        if (!$article) {
            return response()->json(['message' => 'Article not found'], 404);
        }

        $authenticatedUser = Auth::user();

        // Authorization: User must be the author OR an admin to delete
        if ($authenticatedUser->iduser !== $article->user_id && $authenticatedUser->role !== 'admin') {
            return response()->json(['message' => 'You do not have permission to delete this article'], 403);
        }

        $article->delete();

        return response()->json(['message' => 'Article deleted successfully']);
    }


}
