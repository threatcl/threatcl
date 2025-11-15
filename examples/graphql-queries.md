# GraphQL Query Examples

This file contains example GraphQL queries you can run against the threatcl GraphQL server.

## Starting the Server

First, start the server with the examples directory:

```bash
threatcl server -dir ./examples
```

Then navigate to `http://localhost:8080` to access the GraphQL Playground, or use these queries programmatically.

## Basic Queries

### 1. Get Statistics

Get a quick overview of all threat models:

```graphql
query GetStats {
  stats {
    totalThreatModels
    totalThreats
    totalInformationAssets
    totalControls
    implementedControls
    averageRiskReduction
  }
}
```

### 2. List All Threat Models

Get a simple list of all threat model names and authors:

```graphql
query ListThreatModels {
  threatModels {
    name
    author
    description
  }
}
```

### 3. Get a Specific Threat Model

Retrieve details for a single threat model by name:

```graphql
query GetTowerOfLondon {
  threatModel(name: "Tower of London") {
    name
    author
    description
    link
    sourceFile
    createdAt
    updatedAt
  }
}
```

## Filtering Queries

### 4. Internet-Facing Threat Models

Find all threat models that are internet-facing:

```graphql
query InternetFacingModels {
  threatModels(filter: { internetFacing: true }) {
    name
    author
    attributes {
      internetFacing
      initiativeSize
    }
  }
}
```

### 5. New Initiatives

Find all threat models marked as new initiatives:

```graphql
query NewInitiatives {
  threatModels(filter: { newInitiative: true }) {
    name
    author
    attributes {
      newInitiative
      initiativeSize
    }
  }
}
```

### 6. Large Initiatives

Find all large-sized initiatives:

```graphql
query LargeInitiatives {
  threatModels(filter: { initiativeSize: "Large" }) {
    name
    author
    attributes {
      initiativeSize
    }
  }
}
```

### 7. Threats by STRIDE Category

Find all threats categorized as "Spoofing":

```graphql
query SpoofingThreats {
  threats(filter: { stride: ["Spoofing"] }) {
    description
    stride
    impacts
    threatModel {
      name
    }
  }
}
```

### 8. Threats by Impact

Find threats that impact confidentiality:

```graphql
query ConfidentialityThreats {
  threats(filter: { impacts: ["Confidentiality"] }) {
    description
    impacts
    stride
    threatModel {
      name
    }
  }
}
```

### 9. Confidential Information Assets

Find all assets classified as confidential:

```graphql
query ConfidentialAssets {
  informationAssets(classification: "Confidential") {
    name
    description
    informationClassification
    threatModel {
      name
    }
  }
}
```

## Detailed Queries

### 10. Threat Model with All Details

Get complete information about a threat model:

```graphql
query CompleteThreatModel {
  threatModel(name: "Tower of London") {
    name
    author
    description
    link
    sourceFile

    attributes {
      newInitiative
      internetFacing
      initiativeSize
    }

    informationAssets {
      name
      description
      informationClassification
    }

    threats {
      description
      impacts
      stride
      controls {
        name
        description
        implemented
        implementationNotes
        riskReduction
      }
    }

    useCases {
      description
    }

    exclusions {
      description
    }

    thirdPartyDependencies {
      name
      description
      saas
      payingCustomer
      openSource
      infrastructure
      uptimeDependency
      uptimeNotes
    }
  }
}
```

### 11. All Threats with Controls

Get all threats and their associated controls:

```graphql
query AllThreatsWithControls {
  threatModels {
    name
    threats {
      description
      impacts
      stride
      controls {
        name
        description
        implemented
        riskReduction
      }
    }
  }
}
```

### 12. Threat Models with Data Flow Diagrams

Find threat models that have DFDs:

```graphql
query ModelsWithDFDs {
  threatModels {
    name
    author
    dataFlowDiagrams {
      name
      processes {
        name
        trustZone
      }
      dataStores {
        name
        trustZone
        informationAsset
      }
      externalElements {
        name
        trustZone
      }
      flows {
        name
        from
        to
      }
      trustZones {
        name
      }
    }
  }
}
```

## Analysis Queries

### 13. Security Control Coverage

Analyze which threat models have the most controls:

```graphql
query ControlCoverage {
  threatModels {
    name
    author
    threats {
      description
      controls {
        name
        implemented
      }
    }
  }
}
```

### 14. Implementation Status

Find threats with unimplemented controls:

```graphql
query UnimplementedControls {
  threatModels {
    name
    threats {
      description
      controls {
        name
        implemented
        riskReduction
      }
    }
  }
}
```

Note: You'll need to filter client-side for `implemented: false`.

### 15. Risk Reduction Analysis

Analyze risk reduction across all controls:

```graphql
query RiskReductionAnalysis {
  threatModels {
    name
    threats {
      description
      controls {
        name
        implemented
        riskReduction
      }
    }
  }

  stats {
    totalControls
    implementedControls
    averageRiskReduction
  }
}
```

### 16. Third-Party Dependency Audit

Find all third-party dependencies and their criticality:

```graphql
query ThirdPartyAudit {
  threatModels {
    name
    thirdPartyDependencies {
      name
      description
      saas
      openSource
      uptimeDependency
      infrastructure
    }
  }
}
```

## Multiple Queries in One Request

### 17. Dashboard Data

Get all data needed for a dashboard in one query:

```graphql
query Dashboard {
  statistics: stats {
    totalThreatModels
    totalThreats
    totalInformationAssets
    totalControls
    implementedControls
    averageRiskReduction
  }

  recentModels: threatModels {
    name
    author
    updatedAt
    attributes {
      internetFacing
      initiativeSize
    }
  }

  criticalAssets: informationAssets(classification: "Confidential") {
    name
    threatModel {
      name
    }
  }

  allThreats: threats {
    description
    stride
    threatModel {
      name
    }
  }
}
```

### 18. Security Posture Report

Generate a comprehensive security posture report:

```graphql
query SecurityPostureReport {
  stats {
    totalThreatModels
    totalThreats
    totalControls
    implementedControls
    averageRiskReduction
  }

  internetFacing: threatModels(filter: { internetFacing: true }) {
    name
    threats {
      description
      impacts
      controls {
        implemented
      }
    }
  }

  confidentialData: informationAssets(classification: "Confidential") {
    name
    description
    threatModel {
      name
    }
  }
}
```

## Advanced Queries

### 19. Using Query Variables

Define reusable queries with variables:

```graphql
query GetModelByName($modelName: String!) {
  threatModel(name: $modelName) {
    name
    author
    description
    threats {
      description
      impacts
    }
  }
}
```

Variables:
```json
{
  "modelName": "Tower of London"
}
```

### 20. Fragments for Reusable Fields

Use fragments to avoid repeating field selections:

```graphql
fragment ThreatDetails on Threat {
  description
  impacts
  stride
  controls {
    name
    implemented
    riskReduction
  }
}

query ModelsWithThreatDetails {
  threatModels {
    name
    author
    threats {
      ...ThreatDetails
    }
  }

  specificModel: threatModel(name: "Tower of London") {
    name
    threats {
      ...ThreatDetails
    }
  }
}
```

## Client-Side Filtering Examples

While the API provides server-side filtering, sometimes you need client-side filtering. Here are some examples using JavaScript:

### 21. Find Threats Without Implemented Controls

```javascript
const query = `
  query {
    threatModels {
      name
      threats {
        description
        controls {
          name
          implemented
        }
      }
    }
  }
`;

// Filter client-side
const threatsWithoutControls = data.threatModels.flatMap(tm =>
  tm.threats.filter(threat =>
    threat.controls.every(control => !control.implemented)
  ).map(threat => ({
    model: tm.name,
    threat: threat.description
  }))
);
```

### 22. Calculate Control Implementation Rate

```javascript
const query = `
  query {
    threatModels {
      name
      threats {
        controls {
          implemented
        }
      }
    }
  }
`;

// Calculate implementation rate per model
const implementationRates = data.threatModels.map(tm => {
  const allControls = tm.threats.flatMap(t => t.controls);
  const implemented = allControls.filter(c => c.implemented).length;
  return {
    model: tm.name,
    rate: (implemented / allControls.length * 100).toFixed(1)
  };
});
```

## Tips

1. **Use the Playground**: The GraphQL Playground at `http://localhost:8080` provides autocomplete, documentation, and query validation.

2. **Introspection**: You can query the schema itself to discover available types and fields:
   ```graphql
   query {
     __schema {
       types {
         name
         fields {
           name
         }
       }
     }
   }
   ```

3. **Aliases**: Use aliases to fetch the same field with different arguments:
   ```graphql
   query {
     small: threatModels(filter: { initiativeSize: "Small" }) { name }
     large: threatModels(filter: { initiativeSize: "Large" }) { name }
   }
   ```

4. **Comments**: GraphQL supports comments with `#`:
   ```graphql
   query {
     # Get all internet-facing models
     threatModels(filter: { internetFacing: true }) {
       name
     }
   }
   ```

## Next Steps

- Explore the full API documentation: [docs/graphql-api.md](../docs/graphql-api.md)
- Try combining multiple queries to build custom reports
- Integrate the API into your security dashboards and workflows
- Use file watching (`-watch`) to keep data synchronized
