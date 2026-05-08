import { PageHeader } from "@/components/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function Users() {
  return (
    <>
      <PageHeader title="Users" description="User management." />
      <div className="p-8">
        <Card>
          <CardHeader>
            <CardTitle>Placeholder</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            User list + create/disable lands in M7. The API is ready: GET /api/users, POST /api/users,
            PATCH /api/users/{"{id}"}, DELETE /api/users/{"{id}"} (admin-only).
          </CardContent>
        </Card>
      </div>
    </>
  );
}
