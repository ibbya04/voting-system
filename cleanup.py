import os
import glob

files_to_delete = [
    "public_keys.json",
    "ballots.json",
    "tallier_public.pem",
    "tallier_private.pem",
    "shamir_params.json",
    "admin_private.pem",
    "admin_public.pem",
]

# Add all trustee share files
files_to_delete.extend(glob.glob("trustee_*.share"))

# Add all voter private key files
files_to_delete.extend(glob.glob("private_key_*.pem"))

deleted = 0
for f in files_to_delete:
    if os.path.exists(f):
        os.remove(f)
        print(f"Deleted: {f}")
        deleted += 1

print(f"\nCleanup complete. {deleted} files deleted.")