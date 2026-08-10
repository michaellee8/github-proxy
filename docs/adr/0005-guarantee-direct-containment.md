# Guarantee direct repository containment

The Broker guarantees that it exercises an Upstream Credential directly against
only the Target Repository, but it does not guarantee containment of downstream
effects caused by that repository's workflows, webhooks, or other automation.
Preventing every indirect effect would require control over GitHub configuration
and external systems that the Broker does not have; high-impact direct operations
remain independently grantable and repository owners must secure their automation
boundary.
