<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Article;
use App\Models\Comment;
use App\Models\User; // For type hinting Auth user
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use OpenApi\Annotations as OA;

class CommentsController extends Controller
{
    /**
     * @OA\Get(
     *      path="/articles/{article_id}/comments",
     *      operationId="getArticleComments",
     *      tags={"Comments"},
     *      summary="Get comments for an article",
     *      description="Returns a paginated list of comments for a specific article, including replies.",
     *      @OA\Parameter(name="article_id", in="path", description="ID of the article", required=true, @OA\Schema(type="integer")),
     *      @OA\Parameter(name="page", in="query", description="Page number for pagination", required=false, @OA\Schema(type="integer")),
     *      @OA\Response(
     *          response=200,
     *          description="Successful operation",
     *          @OA\JsonContent(
     *              type="object",
     *              @OA\Property(property="current_page", type="integer"),
     *              @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/Comment")),
     *              @OA\Property(property="first_page_url", type="string", format="url"),
     *              @OA\Property(property="from", type="integer"),
     *              @OA\Property(property="last_page", type="integer"),
     *              @OA\Property(property="last_page_url", type="string", format="url"),
     *              @OA\Property(property="links", type="array", @OA\Items(type="object")),
     *              @OA\Property(property="next_page_url", type="string", format="url", nullable=true),
     *              @OA\Property(property="path", type="string", format="url"),
     *              @OA\Property(property="per_page", type="integer"),
     *              @OA\Property(property="prev_page_url", type="string", format="url", nullable=true),
     *              @OA\Property(property="to", type="integer"),
     *              @OA\Property(property="total", type="integer")
     *          )
     *      ),
     *      @OA\Response(response=404, description="Article not found")
     * )
     */
    public function index(Article $article)
    {
        // Fetch top-level comments for the article, eager load user and replies (recursively)
        $comments = $article->comments()
            ->whereNull('parent_id') // Get only top-level comments
            ->with(['user', 'replies']) // Eager load author and replies (replies will also eager load their user and sub-replies due to model setup)
            ->orderBy('created_at', 'desc')
            ->paginate(10); // Adjust pagination as needed

        return response()->json($comments);
    }

    /**
     * @OA\Post(
     *      path="/articles/{article_id}/comments",
     *      operationId="storeComment",
     *      tags={"Comments"},
     *      summary="Create a new comment or reply",
     *      description="Creates a new comment on an article. Can also be a reply to an existing comment if parent_id is provided.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(name="article_id", in="path", description="ID of the article to comment on", required=true, @OA\Schema(type="integer")),
     *      @OA\RequestBody(
     *          required=true,
     *          description="Comment data",
     *          @OA\JsonContent(ref="#/components/schemas/CommentInput")
     *      ),
     *      @OA\Response(response=201, description="Comment created successfully", @OA\JsonContent(ref="#/components/schemas/Comment")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=404, description="Article or Parent Comment not found"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function store(Request $request, Article $article)
    {
        $validator = Validator::make($request->all(), [
            'content' => 'required|string|max:5000',
            'parent_id' => 'nullable|integer|exists:comments,id', // Ensure parent_id exists if provided
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $validatedData = $validator->validated();
        $parentIdToStore = $validatedData['parent_id'] ?? null;

        // If a specific parent_id is provided (i.e., it's not null), validate it.
        // The 'exists:comments,id' rule already ensures $validatedData['parent_id'] (if not null) is a valid comment ID.
        // This check further ensures it belongs to the correct article.
        if ($parentIdToStore !== null) {
            $parentComment = Comment::find($parentIdToStore);
            if (!$parentComment || $parentComment->article_id !== $article->idarticles) {
                return response()->json(['message' => 'Parent comment not found or does not belong to this article.'], 404);
            }
        }
        $comment = $article->comments()->create([
            'content' => $validatedData['content'],
            'user_id' => Auth::id(),
            'parent_id' => $parentIdToStore,
        ]);

        $comment->load('user', 'replies'); // Load user and any potential (though unlikely for new comment) replies

        return response()->json($comment, 201);
    }

    /**
     * @OA\Put(
     *      path="/comments/{comment_id}",
     *      operationId="updateComment",
     *      tags={"Comments"},
     *      summary="Update an existing comment",
     *      description="Updates an existing comment. Only the author or an admin can perform this action.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(name="comment_id", in="path", description="ID of the comment to update", required=true, @OA\Schema(type="integer")),
     *      @OA\RequestBody(
     *          required=true,
     *          description="Comment data to update",
     *          @OA\JsonContent(
     *              required={"content"},
     *              @OA\Property(property="content", type="string", example="Updated comment content.")
     *          )
     *      ),
     *      @OA\Response(response=200, description="Comment updated successfully", @OA\JsonContent(ref="#/components/schemas/Comment")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Not authorized to update this comment"),
     *      @OA\Response(response=404, description="Comment not found"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function update(Request $request, Comment $comment)
    {
        /** @var User $user */
        $user = Auth::user();

        // Authorization check
        if ($user->iduser !== $comment->user_id && $user->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. You are not authorized to update this comment.'], 403);
        }

        $validator = Validator::make($request->all(), [
            'content' => 'required|string|max:5000',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $comment->update($validator->validated());
        $comment->load('user', 'replies');

        return response()->json($comment);
    }

    /**
     * @OA\Delete(
     *      path="/comments/{comment_id}",
     *      operationId="deleteComment",
     *      tags={"Comments"},
     *      summary="Delete a comment",
     *      description="Deletes an existing comment. Only the author or an admin can perform this action. Deleting a comment will also delete its replies if cascade is set.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(name="comment_id", in="path", description="ID of the comment to delete", required=true, @OA\Schema(type="integer")),
     *      @OA\Response(
     *          response=200,
     *          description="Comment deleted successfully",
     *          @OA\JsonContent(@OA\Property(property="message", type="string", example="Comment deleted successfully"))
     *      ),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Not authorized to delete this comment"),
     *      @OA\Response(response=404, description="Comment not found")
     * )
     */
    public function destroy(Comment $comment)
    {
        /** @var User $user */
        $user = Auth::user();

        // Authorization check
        if ($user->iduser !== $comment->user_id && $user->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. You are not authorized to delete this comment.'], 403);
        }

        // The 'onDelete('cascade')' in the migration for parent_id will handle deleting replies.
        $comment->delete();

        return response()->json(['message' => 'Comment deleted successfully']);
    }
}
