# SolarWinds Audit Log — Action and Keyword Catalog

- Log type: `SOLARWINDS_KSS`
- Discovery field: `metadata.description` (`$desc` when bound in YARA-L)
- Catalog: 66 internal IDs, not native SolarWinds event IDs.
- Basis: supplied audit messages. Classifications are proposed; vendor semantics and regex execution remain unverified.

## Action and keyword reference

| ID | Category | Action | Discovery keyword or pattern |
|---|---|---|---|
| SW001 | Maintenance | Create schedule | `added new schedule` + `maintenancewindow` |
| SW002 | Maintenance | Assign entity | `assigned new entity to` |
| SW003 | Maintenance | Remove entity | `removed entity from` |
| SW013 | Maintenance | Execute maintenance | `maintenance` + `was performed for` |
| SW017 | Node | Unmanage node | `unmanaged node` |
| SW018 | Node | Unmanage entity with duration | `unmanaged entity` + `from` + `to` |
| SW020 | Node | Remanage node | `remanaged node` |
| SW026 | Node | Delete node | `deleted node` |
| SW036 | Node | Create node | `created node` + `with log monitoring` |
| SW043 | Node | Modify unmanage duration | `property unmanageuntil` |
| SW044 | Node | Modify custom property | `changed custom property` |
| SW025 | Interface | Delete interface | `deleted interface` |
| SW030 | Interface | Change monitoring state | `set interface` + `managed` or `unmanaged` |
| SW037 | Interface | Create interface | `created interface` |
| SW042 | Interface | Change bandwidth | `changed inbandwidth of interface` or `changed outbandwidth of interface` |
| SW059 | Interface | Change statistics collection | `changed statcollection of interface` |
| SW061 | Interface | Change polling interval | `changed pollinterval of interface` |
| SW066 | Interface | Change caption | `changed caption of interface` |
| SW004 | Polling | Reassign engine | `changed polling engine of` |
| SW005 | Polling | Disable technology polling | `changed technology` + `enabled=false` |
| SW006 | Polling | Enable technology polling | `changed technology` + `enabled=true` |
| SW007 | Polling | Initiate engine restart | `initiated solarwinds orion module engine restart` |
| SW011 | Polling | Modify PerfStack polling | `perfstack.allowrealtimepolling` |
| SW008 | Resource | Set monitored resource state | `set resource` + `true` or `false` |
| SW019 | Resource | Remove resource | `removed resource` |
| SW027 | Resource | Delete volume | `deleted volume` |
| SW033 | Resource | Create volume | `created volume` |
| SW053 | Resource | Add resource | `added resource` + `to` |
| SW009 | Alert | Modify note | `has changed alert note` |
| SW014 | Alert | Modify integration state | `integration state for alertid` |
| SW024 | Alert | Delete alert | `deleted alert with id` |
| SW035 | Alert | Enable or disable alert | `enabled alert` or `disabled alert` |
| SW050 | Alert | Modify reset condition | `changed alert` + `"reset" changed` |
| SW051 | Alert | Modify trigger condition | `changed alert` + `"trigger" changed` |
| SW052 | Alert | Modify frequency | `changed alert` + `"frequency" from` |
| SW010 | Account | Modify permissions | `changed account` |
| SW023 | Account | Delete account | `deleted account` |
| SW034 | Account | Change enabled state | `disabled account` or `changed account` + `enabled:` |
| SW040 | Account | Change password | `changed the password for user` |
| SW058 | Account | Create account | `created account` |
| SW022 | Authentication | Failed login | `made an unsuccessful attempt to login` |
| Pending | Authentication | Successful login | `logged in from` |
| Pending | Authentication | Logout | `logged out from` |
| SW032 | Credential | Delete credential | `deleted credentials` |
| SW057 | Credential | Create credential | `created credentials` |
| SW062 | Credential | Modify privacy password | `property privacypassword` |
| SW063 | Credential | Modify authentication algorithm | `property authenticationtype` |
| SW064 | Credential | Modify privacy algorithm | `property privacytype` |
| SW065 | Credential | Modify authentication password | `property authenticationpassword` |
| SW015 | Platform | Modify certificate hostname validation | `webpagecheckoncertificatenamemismatch` |
| SW045 | Platform | Modify certificate chain validation | `webpagecheckoncertificatechainerrors` |
| SW046 | Platform | Modify PDF certificate validation | `checkoncertificatechainerrors` or `checkoncertificatechainerrorsandnamemismatch` |
| SW016 | Platform | Modify Windows event collection query | `logmanagement.windowsevents.settings.query` |
| SW028 | Platform | Modify node log monitoring | `log monitoring on node` |
| SW054 | Agent | Manual deployment (object unknown) | `was manually deployed on the server` |
| SW055 | Agent | Initiate agent restart | `has initiated agent service restart on` |
| SW031 | Dashboard | Delete widget | `deleted widget` |
| SW038 | Dashboard | Modify view layout | `changed view` |
| SW039 | Dashboard | Modify widget | `changed widget` |
| SW041 | Dashboard | Modify resource title | `changed resource` + `resourcetitle` |
| SW049 | Dashboard | Modify grouping | `changed dashboard` |
| SW056 | Dashboard | Delete dashboard resource | `deleted resource` + `from` + `view` |
| SW060 | Dashboard | Modify resource position | `changed resource` + `position` |
| SW012 | Report | Modify scheduler setting | `reportscheduler_groupingvalue` |
| SW021 | Report | Execute scheduled report | `ran schedule` + `report` |
| SW029 | Report | Generate report | `generated report` |
| SW047 | Report | Enable report schedule | `enabled report schedule` |
| SW048 | Report | Modify report title | `changed report` + `"title" from` |

## Observed property keywords

| Category | Properties |
|---|---|
| Account | `enabled`, `canclearevents`, `allowmanagedashboards`, `alloworionmapsmanagement`, `allowuploadimagestoorionmaps`, `reportfolder`, `alertcategory` |
| Dashboard | `columns`, `column2width`, `column3width`, `displayname`, `type`, `resourcetitle`, `position`, `groupid`, `groupmembername`, `grouprank` |
| Interface | `inbandwidth`, `outbandwidth`, `statcollection`, `pollinterval`, `caption` |
| Alert | `trigger`, `reset`, `frequency` |
| Credential | `privacypassword`, `authenticationpassword`, `authenticationtype`, `privacytype` |
| Node | `unmanageuntil`, `dashboard_used` |
| Maintenance | `unmanage now`, `specific date`, `maintenancewindow` |

## Master action vocabulary

| Action | Keywords |
|---|---|
| Create | `created`, `added` |
| Modify | `changed`, `set` |
| Delete | `deleted`, `removed` |
| Enable | `enabled`, `enabled=true` |
| Disable | `disabled`, `enabled=false` |
| Assign | `assigned new entity to` |
| Unassign | `removed entity from` |
| Suspend | `unmanaged`, `unmanageuntil` |
| Restore | `remanaged`, `managed` |
| Execute | `was performed`, `ran schedule`, `generated report` |
| Restart | `initiated`, `restart` |
| Deploy | `was manually deployed` |
| Authenticate | `logged in`, `unsuccessful attempt to login` |
| Terminate session | `logged out` |

## Proposed detection rule families and research priority

| Category | Rule family (SolarWinds_ prefix) | Priority |
|---|---|---|
| Alert | Alert_Configuration_Modification | Very high |
| Platform | Security_Relevant_Platform_Configuration_Change | Very high |
| Credential | Credential_Management_Modification; Credential_Algorithm_Downgrade | Very high |
| Account | Account_Management_Modification | Very high |
| Authentication | Multiple_Failed_Login_Attempts; Successful_Login_After_Multiple_Failures | High |
| Maintenance | Maintenance_Schedule_Modification | High |
| Node | Node_Monitoring_Modification | High |
| Interface | Interface_Monitoring_Modification | High |
| Polling | Polling_Engine_Reassignment; Technology_Polling_Modification; Module_Engine_Restart | High |
| Agent | Agent_Management_Modification | Medium |
| Resource | Resource_Monitoring_Modification | Medium |
| Dashboard | Dashboard_Configuration_Modification | Low |
| Report | Report_Configuration_Modification | Low |

## Observed security-sensitive changes

- Authentication algorithm: `sha256` to `sha1` (SW063).
- Privacy algorithm: `aes128` to `des56` (SW064).
- Certificate validation settings: `true` to `false` (SW015, SW045, SW046).
- Account permission: `canclearevents: true` (SW010); does not prove events were cleared.
- Alert frequency: `300` to `30` (SW052); units unverified.
- Interface bandwidth: `1000000000` to `200000000` (SW042); units and impact unverified.
- Node unmanage end time: year 9999 to October 26, 2026 (SW043); monitoring restoration unconfirmed.

## Discovery query example

```yaral
metadata.log_type = "SOLARWINDS_KSS"
metadata.description = $desc
re.regex($desc, `created|added|changed|deleted|removed|enabled|disabled|unmanaged|remanaged|assigned|restart|logged in|logged out`) nocase
match:
    $desc
outcome:
    $count = count(metadata.id)
order:
    $count desc
```

## Limitations and future work

- Keywords are for discovery, not production detection or blanket exclusions.
- Mixed-property messages may contain previously unknown security-relevant properties. Preserve raw records.
- Successful login and logout are pending full sample messages.
- SW054 does not identify the deployed object.
- Schedule names such as `specific date` do not independently prove maintenance task type.
- Verify native audit action IDs, raw-to-UDM mapping, property meanings, and actual security impact before production deployment.
- Priorities are proposed research priorities, not measured risk or final alert severity.
- Query syntax and matching have not been executed in Google SecOps.
